from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Any
from urllib.parse import urlencode

from .config import Settings
from .database import BaseStore, utcnow
from .security import (
    SignedValues,
    digest,
    ip_digest,
    random_token,
    referrer_host,
    user_agent_digest,
    validate_target_url,
)
from .shortener import ShortenerClient


@dataclass(slots=True)
class StartedFlow:
    flow_id: str
    cookie: str
    challenge: str


@dataclass(slots=True)
class VerifiedAccess:
    target_url: str
    link_id: str


class ProtectionDenied(Exception):
    def __init__(self, reason: str, status_code: int = 403) -> None:
        self.reason = reason
        self.status_code = status_code
        super().__init__(reason)


class ProtectionService:
    def __init__(
        self,
        settings: Settings,
        store: BaseStore,
        shortener: ShortenerClient | None = None,
    ) -> None:
        self.settings = settings
        self.store = store
        self.shortener = shortener or ShortenerClient(settings)
        self.signed = SignedValues(settings.secret_key)

    async def create_link(
        self,
        target_url: str,
        *,
        user_id: int | None = None,
        expires_in: int | None = None,
        max_uses: int = 1,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        target_url = validate_target_url(target_url)
        now = utcnow()
        seconds = expires_in or self.settings.link_expiry_seconds
        seconds = max(60, min(int(seconds), 60 * 60 * 24 * 365))
        max_uses = max(1, min(int(max_uses), 100000))
        link_id = random_token(12)
        document = {
            "id": link_id,
            "target_url": target_url,
            "user_id": user_id,
            "metadata": metadata or {},
            "created_at": now,
            "expires_at": now + timedelta(seconds=seconds),
            "max_uses": max_uses,
            "successful_access": 0,
            "blocked_access": 0,
            "enabled": True,
        }
        await self.store.create_link(document)
        await self._event("link_created", link_id=link_id, user_id=user_id)
        return {**document, "protected_url": f"{self.settings.public_base_url}/go/{link_id}"}

    async def start_flow(self, link_id: str, user_agent: str, ip: str) -> StartedFlow:
        link = await self._active_link(link_id)
        flow_id = random_token(12)
        raw_challenge = random_token(18)
        now = utcnow()
        flow = {
            "id": flow_id,
            "link_id": link_id,
            "state": "started",
            "challenge_hash": digest(self.settings.secret_key, raw_challenge),
            "nonce_hash": None,
            "short_url": None,
            "created_at": now,
            "activated_at": None,
            "expires_at": now + timedelta(seconds=self.settings.flow_ttl_seconds),
            "consumed_at": None,
            "ua_hash": user_agent_digest(self.settings.secret_key, user_agent),
            "ip_hash": ip_digest(self.settings.secret_key, ip),
        }
        await self.store.create_flow(flow)
        await self._event("flow_started", link_id=link_id, flow_id=flow_id, ip=ip)
        signed_challenge = self.signed.challenge(flow_id, link_id, raw_challenge)
        return StartedFlow(
            flow_id=flow_id,
            cookie=self.signed.cookie(flow_id, link_id),
            challenge=signed_challenge,
        )

    async def continue_flow(
        self,
        link_id: str,
        cookie_value: str,
        challenge_value: str,
        user_agent: str,
        ip: str,
    ) -> str:
        try:
            cookie = self.signed.read_cookie(cookie_value, self.settings.flow_ttl_seconds)
            challenge = self.signed.read_challenge(challenge_value, self.settings.flow_ttl_seconds)
        except Exception as exc:
            await self.deny("invalid_session", link_id=link_id, ip=ip)
            raise ProtectionDenied("invalid_session") from exc

        if cookie["link_id"] != link_id or challenge["link_id"] != link_id:
            await self.deny("session_mismatch", link_id=link_id, ip=ip)
            raise ProtectionDenied("session_mismatch")
        if cookie["flow_id"] != challenge["flow_id"]:
            await self.deny("session_mismatch", link_id=link_id, ip=ip)
            raise ProtectionDenied("session_mismatch")

        await self._active_link(link_id)
        flow = await self.store.get_flow(cookie["flow_id"])
        try:
            self._validate_flow_identity(flow, link_id, user_agent, ip)
        except ProtectionDenied as exc:
            await self.deny(exc.reason, link_id=link_id, flow_id=cookie["flow_id"], ip=ip)
            raise
        if not flow or flow["state"] != "started":
            await self.deny("replay_detected", link_id=link_id, flow_id=cookie["flow_id"], ip=ip)
            raise ProtectionDenied("replay_detected")
        expected = digest(self.settings.secret_key, str(challenge["challenge"]))
        if expected != flow["challenge_hash"]:
            await self.deny("invalid_challenge", link_id=link_id, flow_id=flow["id"], ip=ip)
            raise ProtectionDenied("invalid_challenge")

        nonce = random_token(24)
        query = urlencode({"flow": flow["id"], "nonce": nonce})
        callback_url = f"{self.settings.public_base_url}/verify/{link_id}?{query}"
        short_url = await self.shortener.shorten(callback_url)
        activated_at = utcnow()
        activated = await self.store.activate_flow(
            flow["id"], digest(self.settings.secret_key, nonce), short_url, activated_at
        )
        if not activated:
            await self.deny("replay_detected", link_id=link_id, flow_id=flow["id"], ip=ip)
            raise ProtectionDenied("replay_detected")
        await self._event("shortener_opened", link_id=link_id, flow_id=flow["id"], ip=ip)
        return short_url

    async def verify(
        self,
        link_id: str,
        flow_id: str,
        nonce: str,
        cookie_value: str,
        user_agent: str,
        ip: str,
        referrer: str,
    ) -> VerifiedAccess:
        if not cookie_value:
            await self.deny("direct_paste", link_id=link_id, flow_id=flow_id, ip=ip)
            raise ProtectionDenied("direct_paste")
        try:
            cookie = self.signed.read_cookie(cookie_value, self.settings.flow_ttl_seconds)
        except Exception as exc:
            await self.deny("invalid_session", link_id=link_id, flow_id=flow_id, ip=ip)
            raise ProtectionDenied("invalid_session") from exc

        if cookie["link_id"] != link_id or cookie["flow_id"] != flow_id:
            await self.deny("session_mismatch", link_id=link_id, flow_id=flow_id, ip=ip)
            raise ProtectionDenied("session_mismatch")

        link = await self._active_link(link_id)
        flow = await self.store.get_flow(flow_id)
        try:
            self._validate_flow_identity(flow, link_id, user_agent, ip)
        except ProtectionDenied as exc:
            await self.deny(exc.reason, link_id=link_id, flow_id=flow_id, ip=ip)
            raise
        if not flow or flow.get("state") != "shortener":
            await self.deny("replay_detected", link_id=link_id, flow_id=flow_id, ip=ip)
            raise ProtectionDenied("replay_detected")
        if digest(self.settings.secret_key, nonce) != flow.get("nonce_hash"):
            await self.deny("invalid_token", link_id=link_id, flow_id=flow_id, ip=ip)
            raise ProtectionDenied("invalid_token")

        now = utcnow()
        if flow["expires_at"] <= now:
            await self.deny("flow_expired", link_id=link_id, flow_id=flow_id, ip=ip)
            raise ProtectionDenied("flow_expired", 410)
        activated_at = flow.get("activated_at")
        if (
            not self.settings.demo_mode
            and (
                not activated_at
                or (now - activated_at).total_seconds() < self.settings.min_completion_seconds
            )
        ):
            await self.deny("completed_too_fast", link_id=link_id, flow_id=flow_id, ip=ip)
            raise ProtectionDenied("completed_too_fast")

        if self.settings.strict_referrer and self.settings.shortener_domain:
            host = referrer_host(referrer)
            allowed = self.settings.shortener_domain.lstrip(".")
            if host != allowed and not host.endswith(f".{allowed}"):
                await self.deny("invalid_referrer", link_id=link_id, flow_id=flow_id, ip=ip)
                raise ProtectionDenied("invalid_referrer")

        consumed = await self.store.consume_flow(flow_id, now)
        if not consumed:
            await self.deny("replay_detected", link_id=link_id, flow_id=flow_id, ip=ip)
            raise ProtectionDenied("replay_detected")
        claimed = await self.store.claim_link_success(link_id, now)
        if not claimed:
            await self.deny("link_used", link_id=link_id, flow_id=flow_id, ip=ip)
            raise ProtectionDenied("link_used", 410)
        await self._event(
            "access_granted", link_id=link_id, flow_id=flow_id, user_id=link.get("user_id"), ip=ip
        )
        return VerifiedAccess(target_url=link["target_url"], link_id=link_id)

    async def deny(
        self,
        reason: str,
        *,
        link_id: str | None = None,
        flow_id: str | None = None,
        ip: str = "unknown",
    ) -> None:
        if link_id and await self.store.get_link(link_id):
            await self.store.increment_link(link_id, success=False)
        await self._event("access_denied", link_id=link_id, flow_id=flow_id, reason=reason, ip=ip)

    async def _active_link(self, link_id: str) -> dict[str, Any]:
        link = await self.store.get_link(link_id)
        if not link:
            raise ProtectionDenied("link_not_found", 404)
        now = utcnow()
        if not link.get("enabled", True):
            raise ProtectionDenied("link_disabled", 410)
        if link["expires_at"] <= now:
            raise ProtectionDenied("link_expired", 410)
        if int(link.get("successful_access", 0)) >= int(link.get("max_uses", 1)):
            raise ProtectionDenied("link_used", 410)
        return link

    def _validate_flow_identity(
        self,
        flow: dict[str, Any] | None,
        link_id: str,
        user_agent: str,
        ip: str,
    ) -> None:
        if not flow or flow.get("link_id") != link_id:
            raise ProtectionDenied("flow_not_found", 404)
        if flow.get("ua_hash") != user_agent_digest(self.settings.secret_key, user_agent):
            raise ProtectionDenied("browser_mismatch")
        if self.settings.bind_ip_prefix and flow.get("ip_hash") != ip_digest(self.settings.secret_key, ip):
            raise ProtectionDenied("network_mismatch")

    async def _event(
        self,
        event_type: str,
        *,
        link_id: str | None = None,
        flow_id: str | None = None,
        user_id: int | None = None,
        reason: str | None = None,
        ip: str | None = None,
    ) -> None:
        await self.store.record_event(
            {
                "type": event_type,
                "link_id": link_id,
                "flow_id": flow_id,
                "user_id": user_id,
                "reason": reason,
                "ip_hash": ip_digest(self.settings.secret_key, ip) if ip else None,
                "created_at": utcnow(),
            }
        )
