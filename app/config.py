from __future__ import annotations

import os
from dataclasses import dataclass


def _as_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _as_int(value: str | None, default: int) -> int:
    try:
        return int(value) if value is not None else default
    except (TypeError, ValueError):
        return default


def _csv_ints(value: str | None) -> tuple[int, ...]:
    if not value:
        return ()
    result: list[int] = []
    for item in value.split(","):
        item = item.strip()
        if item:
            result.append(int(item))
    return tuple(result)


@dataclass(slots=True)
class Settings:
    app_name: str = "RDX Protect Bot"
    environment: str = "development"
    public_base_url: str = "https://rdx-anti-bypass-veft.vercel.app/"
    secret_key: str = "dev-secret-change-me"
    api_key: str = "dev-api-key-change-me"

    mongodb_uri: str = ""
    mongodb_database: str = "rdx_anti_bypass"

    cookie_name: str = "rdx_ab_flow"
    flow_ttl_seconds: int = 1200
    link_expiry_seconds: int = 86400
    min_completion_seconds: int = 8
    success_redirect_delay_ms: int = 1300
    bind_ip_prefix: bool = True
    strict_referrer: bool = False
    trust_proxy_headers: bool = True

    shortener_name: str = "Configured shortener"
    shortener_domain: str = ""
    shortener_api_url: str = ""
    shortener_api_key: str = ""
    shortener_api_key_param: str = "api"
    shortener_url_param: str = "url"
    shortener_format_param: str = "format"
    shortener_format_value: str = "text"
    demo_mode: bool = True

    bot_token: str = ""
    bot_mode: str = "webhook"
    bot_admin_ids: tuple[int, ...] = ()
    bot_banner_url: str = ""
    updates_url: str = ""
    support_url: str = ""
    owner_username: str = "RDX Developer"
    webhook_secret: str = "change-this-webhook-secret"
    auto_set_webhook: bool = False

    @property
    def secure_cookie(self) -> bool:
        return self.public_base_url.lower().startswith("https://")

    @property
    def is_production(self) -> bool:
        return self.environment.lower() == "production"

    @classmethod
    def from_env(cls) -> "Settings":
        settings = cls(
            app_name=os.getenv("APP_NAME", "RDX Protect Bot").strip(),
            environment=os.getenv("ENVIRONMENT", "development").strip(),
            public_base_url=os.getenv("PUBLIC_BASE_URL", "http://localhost:8000").strip().rstrip("/"),
            secret_key=os.getenv("SECRET_KEY", "dev-secret-change-me").strip(),
            api_key=os.getenv("API_KEY", "dev-api-key-change-me").strip(),
            mongodb_uri=os.getenv("MONGODB_URI", "").strip(),
            mongodb_database=os.getenv("MONGODB_DATABASE", "rdx_anti_bypass").strip(),
            cookie_name=os.getenv("COOKIE_NAME", "rdx_ab_flow").strip(),
            flow_ttl_seconds=_as_int(os.getenv("FLOW_TTL_SECONDS"), 1200),
            link_expiry_seconds=_as_int(os.getenv("LINK_EXPIRY_SECONDS"), 86400),
            min_completion_seconds=_as_int(os.getenv("MIN_COMPLETION_SECONDS"), 8),
            success_redirect_delay_ms=_as_int(os.getenv("SUCCESS_REDIRECT_DELAY_MS"), 1300),
            bind_ip_prefix=_as_bool(os.getenv("BIND_IP_PREFIX"), True),
            strict_referrer=_as_bool(os.getenv("STRICT_REFERRER"), False),
            trust_proxy_headers=_as_bool(os.getenv("TRUST_PROXY_HEADERS"), True),
            shortener_name=os.getenv("SHORTENER_NAME", "Configured shortener").strip(),
            shortener_domain=os.getenv("SHORTENER_DOMAIN", "").strip().lower(),
            shortener_api_url=os.getenv("SHORTENER_API_URL", "").strip(),
            shortener_api_key=os.getenv("SHORTENER_API_KEY", "").strip(),
            shortener_api_key_param=os.getenv("SHORTENER_API_KEY_PARAM", "api").strip(),
            shortener_url_param=os.getenv("SHORTENER_URL_PARAM", "url").strip(),
            shortener_format_param=os.getenv("SHORTENER_FORMAT_PARAM", "format").strip(),
            shortener_format_value=os.getenv("SHORTENER_FORMAT_VALUE", "text").strip(),
            demo_mode=_as_bool(os.getenv("DEMO_MODE"), True),
            bot_token=os.getenv("BOT_TOKEN", "").strip(),
            bot_mode=os.getenv("BOT_MODE", "webhook").strip().lower(),
            bot_admin_ids=_csv_ints(os.getenv("BOT_ADMIN_IDS")),
            bot_banner_url=os.getenv("BOT_BANNER_URL", "").strip(),
            updates_url=os.getenv("UPDATES_URL", "").strip(),
            support_url=os.getenv("SUPPORT_URL", "").strip(),
            owner_username=os.getenv("OWNER_USERNAME", "RDX Developer").strip(),
            webhook_secret=os.getenv("WEBHOOK_SECRET", "change-this-webhook-secret").strip(),
            auto_set_webhook=_as_bool(os.getenv("AUTO_SET_WEBHOOK"), False),
        )
        settings.validate()
        return settings

    def validate(self) -> None:
        if self.flow_ttl_seconds < 30:
            raise ValueError("FLOW_TTL_SECONDS must be at least 30")
        if self.min_completion_seconds < 0:
            raise ValueError("MIN_COMPLETION_SECONDS cannot be negative")
        if self.bot_mode not in {"webhook", "polling", "disabled"}:
            raise ValueError("BOT_MODE must be webhook, polling, or disabled")
        if self.is_production:
            weak = {
                "dev-secret-change-me",
                "dev-api-key-change-me",
                "change-this-webhook-secret",
                "",
            }
            if self.secret_key in weak:
                raise ValueError("Set a strong SECRET_KEY before production deployment")
            if self.api_key in weak:
                raise ValueError("Set a strong API_KEY before production deployment")
            if self.bot_token and self.bot_mode == "webhook" and self.webhook_secret in weak:
                raise ValueError("Set a strong WEBHOOK_SECRET before production deployment")
            if not self.mongodb_uri:
                raise ValueError("MONGODB_URI is required in production")
            if not self.public_base_url.startswith("https://"):
                raise ValueError("PUBLIC_BASE_URL must use HTTPS in production")
            if not self.demo_mode and not self.shortener_api_url:
                raise ValueError("SHORTENER_API_URL is required when DEMO_MODE is false")
