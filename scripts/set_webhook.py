from __future__ import annotations

import asyncio

import httpx

from app.config import Settings


async def main() -> None:
    settings = Settings.from_env()
    url = f"{settings.public_base_url}/api/v1/telegram/setup"
    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(url, headers={"X-API-Key": settings.api_key})
        response.raise_for_status()
        print(response.json())


if __name__ == "__main__":
    asyncio.run(main())
