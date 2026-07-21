from __future__ import annotations

import asyncio
import contextlib
import logging
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

from aiogram.types import Update
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .bot import create_bot_components
from .config import Settings
from .database import BaseStore, MemoryStore, MongoStore
from .schemas import ContinueFlowRequest, CreateLinkRequest
from .security import secure_equal
from .services import ProtectionDenied, ProtectionService

logger = logging.getLogger("rdx_anti_bypass")
BASE_DIR = Path(__file__).resolve().parent


def _serialize(document: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in document.items():
        if key == "target_url":
            continue
        result[key] = value.isoformat() if isinstance(value, datetime) else value
    return result


def _client_ip(request: Request, settings: Settings) -> str:
    if settings.trust_proxy_headers:
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            return forwarded.split(",", 1)[0].strip()
    return request.client.host if request.client else "unknown"


def _denied_context(request: Request, settings: Settings, reason: str) -> dict[str, Any]:
    reason_messages = {
        "direct_paste": "Direct paste or shared callback detected.",
        "invalid_session": "The protected browser session is missing or invalid.",
        "session_mismatch": "This callback belongs to a different browser session.",
        "browser_mismatch": "The browser identity changed during verification.",
        "network_mismatch": "The network changed during verification.",
        "invalid_challenge": "The browser challenge could not be verified.",
        "invalid_token": "The callback token was modified or is invalid.",
        "completed_too_fast": "The shortener was completed faster than allowed.",
        "invalid_referrer": "Please complete the configured shortener normally.",
        "replay_detected": "This one-time callback was already used.",
        "flow_expired": "This browser session has expired.",
        "link_expired": "This protected link has expired.",
        "link_used": "This protected link has already been used.",
        "link_not_found": "The requested protected link does not exist.",
        "link_disabled": "This protected link has been disabled.",
        "flow_not_found": "The verification session could not be found.",
    }
    return {
        "request": request,
        "app_name": settings.app_name,
        "reason": reason,
        "message": reason_messages.get(reason, "We could not process your request due to a security violation."),
        "shortener_name": settings.shortener_name,
        "shortener_domain": settings.shortener_domain,
    }


def create_app(
    settings: Settings | None = None,
    store: BaseStore | None = None,
    service: ProtectionService | None = None,
) -> FastAPI:
    settings = settings or Settings.from_env()
    store = store or (MongoStore(settings.mongodb_uri, settings.mongodb_database) if settings.mongodb_uri else MemoryStore())
    service = service or ProtectionService(settings, store)
    templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

    bot = dispatcher = None
    if settings.bot_token and settings.bot_mode != "disabled":
        bot, dispatcher = create_bot_components(settings, service)

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        await store.initialize()
        polling_task: asyncio.Task[Any] | None = None
        if bot and dispatcher:
            if settings.bot_mode == "polling":
                await bot.delete_webhook(drop_pending_updates=False)
                polling_task = asyncio.create_task(dispatcher.start_polling(bot))
            elif settings.auto_set_webhook:
                await bot.set_webhook(
                    f"{settings.public_base_url}/telegram/webhook/{settings.webhook_secret}",
                    secret_token=settings.webhook_secret,
                )
        try:
            yield
        finally:
            if polling_task:
                polling_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await polling_task
            if bot:
                await bot.session.close()
            await store.close()

    app = FastAPI(
        title=settings.app_name,
        version="1.0.0",
        docs_url=None if settings.is_production else "/docs",
        redoc_url=None,
        lifespan=lifespan,
    )
    app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
    app.state.settings = settings
    app.state.store = store
    app.state.service = service
    app.state.bot = bot
    app.state.dispatcher = dispatcher

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self'; script-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'",
        )
        return response

    async def require_api_key(x_api_key: str = Header(default="")) -> None:
        if not x_api_key or not secure_equal(x_api_key, settings.api_key):
            raise HTTPException(status_code=401, detail="Invalid API key")

    @app.get("/", response_class=HTMLResponse)
    async def home(request: Request):
        return templates.TemplateResponse(
            request=request,
            name="home.html",
            context={"app_name": settings.app_name, "demo_mode": settings.demo_mode},
        )

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {
            "ok": True,
            "service": settings.app_name,
            "version": "1.0.0",
            "database": "mongodb" if settings.mongodb_uri else "memory",
            "shortener_mode": "demo" if settings.demo_mode else "api",
        }

    @app.get("/access-denied", response_class=HTMLResponse, include_in_schema=False)
    async def access_denied(request: Request, reason: str = Query(default="invalid_session", max_length=64)):
        allowed_reasons = {
            "direct_paste",
            "invalid_session",
            "session_mismatch",
            "browser_mismatch",
            "network_mismatch",
            "invalid_challenge",
            "invalid_token",
            "completed_too_fast",
            "invalid_referrer",
            "replay_detected",
            "flow_expired",
            "link_expired",
            "link_used",
            "link_not_found",
            "link_disabled",
            "flow_not_found",
            "shortener_error",
        }
        safe_reason = reason if reason in allowed_reasons else "invalid_session"
        return templates.TemplateResponse(
            request=request,
            name="denied.html",
            context=_denied_context(request, settings, safe_reason),
            status_code=403,
        )

    @app.get("/go/{link_id}", response_class=HTMLResponse)
    async def start_protection(request: Request, link_id: str):
        ip = _client_ip(request, settings)
        try:
            started = await service.start_flow(link_id, request.headers.get("user-agent", ""), ip)
        except ProtectionDenied as exc:
            return templates.TemplateResponse(
                request=request,
                name="denied.html",
                context=_denied_context(request, settings, exc.reason),
                status_code=exc.status_code,
            )
        response = templates.TemplateResponse(
            request=request,
            name="launch.html",
            context={
                "app_name": settings.app_name,
                "link_id": link_id,
                "challenge": started.challenge,
            },
        )
        response.set_cookie(
            settings.cookie_name,
            started.cookie,
            max_age=settings.flow_ttl_seconds,
            secure=settings.secure_cookie,
            httponly=True,
            samesite="lax",
            path="/",
        )
        response.headers["Cache-Control"] = "no-store, private"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response

    @app.post("/go/{link_id}/continue")
    async def continue_protection(request: Request, link_id: str, payload: ContinueFlowRequest):
        ip = _client_ip(request, settings)
        try:
            short_url = await service.continue_flow(
                link_id,
                request.cookies.get(settings.cookie_name, ""),
                payload.challenge,
                request.headers.get("user-agent", ""),
                ip,
            )
        except ProtectionDenied as exc:
            return JSONResponse({"ok": False, "reason": exc.reason}, status_code=exc.status_code)
        except Exception:
            logger.exception("Shortener continuation failed")
            return JSONResponse({"ok": False, "reason": "shortener_error"}, status_code=502)
        return {"ok": True, "redirect": short_url}

    @app.get("/verify/{link_id}", response_class=HTMLResponse)
    async def verify_callback(
        request: Request,
        link_id: str,
        flow: str = Query(default="", min_length=1, max_length=200),
        nonce: str = Query(default="", min_length=1, max_length=500),
    ):
        ip = _client_ip(request, settings)
        try:
            verified = await service.verify(
                link_id,
                flow,
                nonce,
                request.cookies.get(settings.cookie_name, ""),
                request.headers.get("user-agent", ""),
                ip,
                request.headers.get("referer", ""),
            )
        except ProtectionDenied as exc:
            response = templates.TemplateResponse(
                request=request,
                name="denied.html",
                context=_denied_context(request, settings, exc.reason),
                status_code=exc.status_code,
            )
            response.delete_cookie(settings.cookie_name, path="/")
            response.headers["Cache-Control"] = "no-store, private"
            return response
        response = templates.TemplateResponse(
            request=request,
            name="success.html",
            context={
                "app_name": settings.app_name,
                "target_url": verified.target_url,
                "delay_ms": settings.success_redirect_delay_ms,
            },
        )
        response.delete_cookie(settings.cookie_name, path="/")
        response.headers["Cache-Control"] = "no-store, private"
        return response

    @app.post("/api/v1/links", dependencies=[Depends(require_api_key)])
    async def create_link(payload: CreateLinkRequest):
        try:
            link = await service.create_link(
                payload.target_url,
                user_id=payload.user_id,
                expires_in=payload.expires_in,
                max_uses=payload.max_uses,
                metadata=payload.metadata,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return {
            "id": link["id"],
            "protected_url": link["protected_url"],
            "expires_at": link["expires_at"].isoformat(),
            "max_uses": link["max_uses"],
        }

    @app.get("/api/v1/links/{link_id}", dependencies=[Depends(require_api_key)])
    async def link_status(link_id: str):
        link = await store.get_link(link_id)
        if not link:
            raise HTTPException(status_code=404, detail="Link not found")
        return _serialize(link)

    @app.get("/api/v1/links", dependencies=[Depends(require_api_key)])
    async def list_links(limit: int = Query(default=20, ge=1, le=100)):
        return {"items": [_serialize(item) for item in await store.list_links(limit)]}

    @app.get("/api/v1/stats", dependencies=[Depends(require_api_key)])
    async def statistics():
        return await store.stats()

    @app.get("/api/v1/events", dependencies=[Depends(require_api_key)])
    async def events(limit: int = Query(default=25, ge=1, le=200)):
        return {"items": [_serialize(item) for item in await store.list_events(limit)]}

    @app.post("/api/v1/telegram/setup", dependencies=[Depends(require_api_key)])
    async def setup_telegram_webhook():
        if not bot or not dispatcher:
            raise HTTPException(status_code=503, detail="Telegram bot is disabled")
        if settings.bot_mode != "webhook":
            raise HTTPException(status_code=409, detail="BOT_MODE is not webhook")
        url = f"{settings.public_base_url}/telegram/webhook/{settings.webhook_secret}"
        await bot.set_webhook(url, secret_token=settings.webhook_secret)
        return {"ok": True, "webhook_url": url}

    @app.post("/telegram/webhook/{secret}", include_in_schema=False)
    async def telegram_webhook(
        secret: str,
        request: Request,
        x_telegram_bot_api_secret_token: str = Header(default=""),
    ):
        if not bot or not dispatcher:
            raise HTTPException(status_code=503, detail="Telegram bot is disabled")
        if not secure_equal(secret, settings.webhook_secret) or not secure_equal(
            x_telegram_bot_api_secret_token, settings.webhook_secret
        ):
            raise HTTPException(status_code=403, detail="Invalid webhook secret")
        update = Update.model_validate(await request.json(), context={"bot": bot})
        await dispatcher.feed_update(bot, update)
        return {"ok": True}

    return app


app = create_app()
