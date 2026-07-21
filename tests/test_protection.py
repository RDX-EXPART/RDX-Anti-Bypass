from __future__ import annotations

import re
from datetime import timedelta
from urllib.parse import urlparse

from fastapi.testclient import TestClient

from app.config import Settings
from app.database import MemoryStore
from app.database import utcnow
from app.main import create_app


USER_AGENT = "RDX-Test-Browser/1.0"


def build_app():
    settings = Settings(
        app_name="RDX Test Protect",
        public_base_url="http://testserver",
        secret_key="test-secret-that-is-long-and-not-used-in-production",
        api_key="test-api-key",
        demo_mode=True,
        min_completion_seconds=0,
        bind_ip_prefix=False,
        bot_mode="disabled",
    )
    store = MemoryStore()
    return create_app(settings=settings, store=store), settings, store


def test_direct_paste_is_denied_and_same_browser_is_allowed():
    app, settings, _ = build_app()
    api_headers = {"X-API-Key": settings.api_key}
    browser_headers = {"User-Agent": USER_AGENT}

    with TestClient(app) as legitimate:
        created = legitimate.post(
            "/api/v1/links",
            headers=api_headers,
            json={"target_url": "https://example.com/verified", "max_uses": 1},
        )
        assert created.status_code == 200
        protected_path = urlparse(created.json()["protected_url"]).path

        launch = legitimate.get(protected_path, headers=browser_headers)
        assert launch.status_code == 200
        match = re.search(r'data-challenge="([^"]+)"', launch.text)
        assert match

        continued = legitimate.post(
            f"{protected_path}/continue",
            headers=browser_headers,
            json={"challenge": match.group(1)},
        )
        assert continued.status_code == 200
        callback_url = continued.json()["redirect"]
        callback_path = urlparse(callback_url).path + "?" + urlparse(callback_url).query

        with TestClient(app) as bypass_browser:
            denied = bypass_browser.get(callback_path, headers=browser_headers)
            assert denied.status_code == 403
            assert "ACCESS DENIED" in denied.text
            assert "Direct paste or shared callback detected" in denied.text

        granted = legitimate.get(callback_path, headers=browser_headers)
        assert granted.status_code == 200
        assert "ACCESS GRANTED" in granted.text
        assert "https://example.com/verified" in granted.text


def test_callback_nonce_tampering_is_denied():
    app, settings, _ = build_app()
    with TestClient(app) as client:
        created = client.post(
            "/api/v1/links",
            headers={"X-API-Key": settings.api_key},
            json={"target_url": "https://example.com/ok"},
        ).json()
        path = urlparse(created["protected_url"]).path
        launch = client.get(path, headers={"User-Agent": USER_AGENT})
        challenge = re.search(r'data-challenge="([^"]+)"', launch.text).group(1)
        callback = client.post(
            f"{path}/continue",
            headers={"User-Agent": USER_AGENT},
            json={"challenge": challenge},
        ).json()["redirect"]
        parsed = urlparse(callback)
        tampered = parsed.path + "?" + parsed.query.replace("nonce=", "nonce=changed")
        response = client.get(tampered, headers={"User-Agent": USER_AGENT})
        assert response.status_code == 403
        assert "INVALID_TOKEN" in response.text


def test_api_requires_key_and_hides_target_from_status_response():
    app, settings, _ = build_app()
    with TestClient(app) as client:
        assert client.get("/api/v1/stats").status_code == 401
        created = client.post(
            "/api/v1/links",
            headers={"X-API-Key": settings.api_key},
            json={"target_url": "https://example.com/private"},
        ).json()
        status = client.get(
            f"/api/v1/links/{created['id']}", headers={"X-API-Key": settings.api_key}
        )
        assert status.status_code == 200
        assert "target_url" not in status.json()


def test_invalid_target_scheme_is_rejected():
    app, settings, _ = build_app()
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/links",
            headers={"X-API-Key": settings.api_key},
            json={"target_url": "javascript:alert(1)"},
        )
        assert response.status_code == 422


def test_one_time_callback_replay_is_denied():
    app, settings, _ = build_app()
    headers = {"User-Agent": USER_AGENT}
    with TestClient(app) as client:
        created = client.post(
            "/api/v1/links",
            headers={"X-API-Key": settings.api_key},
            json={"target_url": "https://example.com/ok", "max_uses": 2},
        ).json()
        path = urlparse(created["protected_url"]).path
        launch = client.get(path, headers=headers)
        challenge = re.search(r'data-challenge="([^"]+)"', launch.text).group(1)
        cookie = client.cookies.get(settings.cookie_name)
        callback = client.post(
            f"{path}/continue", headers=headers, json={"challenge": challenge}
        ).json()["redirect"]
        parsed = urlparse(callback)
        callback_path = parsed.path + "?" + parsed.query

        assert client.get(callback_path, headers=headers).status_code == 200
        client.cookies.set(settings.cookie_name, cookie)
        replay = client.get(callback_path, headers=headers)
        assert replay.status_code == 403
        assert "REPLAY_DETECTED" in replay.text


def test_expired_link_is_denied_before_flow_starts():
    app, settings, store = build_app()
    with TestClient(app) as client:
        created = client.post(
            "/api/v1/links",
            headers={"X-API-Key": settings.api_key},
            json={"target_url": "https://example.com/expired"},
        ).json()
        store.links[created["id"]]["expires_at"] = utcnow() - timedelta(seconds=1)
        response = client.get(urlparse(created["protected_url"]).path)
        assert response.status_code == 410
        assert "LINK_EXPIRED" in response.text
