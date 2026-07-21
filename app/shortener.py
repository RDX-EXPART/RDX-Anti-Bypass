from __future__ import annotations

from typing import Any
from urllib.parse import quote, urlparse

import httpx

from .config import Settings


class ShortenerError(RuntimeError):
    pass


class ShortenerClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def shorten(self, callback_url: str) -> str:
        if self.settings.demo_mode or not self.settings.shortener_api_url:
            return callback_url

        endpoint = self.settings.shortener_api_url
        params: dict[str, str] = {}
        if "{url}" in endpoint or "{key}" in endpoint:
            endpoint = endpoint.replace("{url}", quote(callback_url, safe=""))
            endpoint = endpoint.replace("{key}", quote(self.settings.shortener_api_key, safe=""))
        else:
            params[self.settings.shortener_url_param] = callback_url
            if self.settings.shortener_api_key:
                params[self.settings.shortener_api_key_param] = self.settings.shortener_api_key
            if self.settings.shortener_format_param and self.settings.shortener_format_value:
                params[self.settings.shortener_format_param] = self.settings.shortener_format_value

        try:
            async with httpx.AsyncClient(timeout=20, follow_redirects=True) as client:
                response = await client.get(endpoint, params=params)
                response.raise_for_status()
        except httpx.HTTPError as exc:
            raise ShortenerError("The shortener API request failed") from exc

        result = self._extract_url(response)
        parsed = urlparse(result)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ShortenerError("The shortener API returned an invalid URL")
        return result

    @staticmethod
    def _extract_url(response: httpx.Response) -> str:
        content_type = response.headers.get("content-type", "").lower()
        if "json" in content_type:
            payload: Any = response.json()
            if isinstance(payload, str):
                return payload.strip()
            if isinstance(payload, dict):
                for key in ("shortenedUrl", "shortened_url", "short_url", "short", "url"):
                    value = payload.get(key)
                    if isinstance(value, str) and value.strip():
                        return value.strip()
                data = payload.get("data")
                if isinstance(data, dict):
                    for key in ("shortenedUrl", "shortened_url", "short_url", "url"):
                        value = data.get(key)
                        if isinstance(value, str) and value.strip():
                            return value.strip()
            raise ShortenerError("No shortened URL was found in the API response")
        return response.text.strip()
