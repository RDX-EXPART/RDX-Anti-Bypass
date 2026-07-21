from __future__ import annotations

import hashlib
import hmac
import ipaddress
import secrets
from typing import Any
from urllib.parse import urlparse

from itsdangerous import BadData, SignatureExpired, URLSafeTimedSerializer


class InvalidSignedValue(Exception):
    pass


def random_token(bytes_count: int = 24) -> str:
    return secrets.token_urlsafe(bytes_count)


def digest(secret_key: str, value: str) -> str:
    return hmac.new(secret_key.encode(), value.encode(), hashlib.sha256).hexdigest()


def secure_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode(), right.encode())


def user_agent_digest(secret_key: str, user_agent: str) -> str:
    normalized = " ".join((user_agent or "unknown").strip().lower().split())
    return digest(secret_key, f"ua:{normalized}")


def ip_prefix(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
        if address.version == 4:
            return str(ipaddress.ip_network(f"{address}/24", strict=False).network_address) + "/24"
        return str(ipaddress.ip_network(f"{address}/64", strict=False).network_address) + "/64"
    except ValueError:
        return "unknown"


def ip_digest(secret_key: str, value: str) -> str:
    return digest(secret_key, f"ip:{ip_prefix(value)}")


def validate_target_url(value: str) -> str:
    value = value.strip()
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https", "tg"}:
        raise ValueError("target_url must use http, https, or tg")
    if parsed.scheme in {"http", "https"} and not parsed.netloc:
        raise ValueError("target_url must include a host")
    return value


def referrer_host(value: str) -> str:
    try:
        return (urlparse(value).hostname or "").lower()
    except ValueError:
        return ""


class SignedValues:
    def __init__(self, secret_key: str) -> None:
        self._cookies = URLSafeTimedSerializer(secret_key, salt="rdx-flow-cookie-v1")
        self._challenges = URLSafeTimedSerializer(secret_key, salt="rdx-flow-challenge-v1")

    def cookie(self, flow_id: str, link_id: str) -> str:
        return self._cookies.dumps({"flow_id": flow_id, "link_id": link_id})

    def read_cookie(self, value: str, max_age: int) -> dict[str, Any]:
        try:
            result = self._cookies.loads(value, max_age=max_age)
        except (BadData, SignatureExpired) as exc:
            raise InvalidSignedValue from exc
        if not isinstance(result, dict) or "flow_id" not in result or "link_id" not in result:
            raise InvalidSignedValue
        return result

    def challenge(self, flow_id: str, link_id: str, challenge: str) -> str:
        return self._challenges.dumps(
            {"flow_id": flow_id, "link_id": link_id, "challenge": challenge}
        )

    def read_challenge(self, value: str, max_age: int) -> dict[str, Any]:
        try:
            result = self._challenges.loads(value, max_age=max_age)
        except (BadData, SignatureExpired) as exc:
            raise InvalidSignedValue from exc
        if not isinstance(result, dict) or not all(
            key in result for key in ("flow_id", "link_id", "challenge")
        ):
            raise InvalidSignedValue
        return result
