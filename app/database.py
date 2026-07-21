from __future__ import annotations

import asyncio
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class BaseStore:
    async def initialize(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def create_link(self, document: dict[str, Any]) -> None:
        raise NotImplementedError

    async def get_link(self, link_id: str) -> dict[str, Any] | None:
        raise NotImplementedError

    async def list_links(self, limit: int = 20) -> list[dict[str, Any]]:
        raise NotImplementedError

    async def create_flow(self, document: dict[str, Any]) -> None:
        raise NotImplementedError

    async def get_flow(self, flow_id: str) -> dict[str, Any] | None:
        raise NotImplementedError

    async def activate_flow(
        self, flow_id: str, nonce_hash: str, short_url: str, activated_at: datetime
    ) -> bool:
        raise NotImplementedError

    async def consume_flow(self, flow_id: str, consumed_at: datetime) -> bool:
        raise NotImplementedError

    async def increment_link(self, link_id: str, success: bool) -> None:
        raise NotImplementedError

    async def claim_link_success(self, link_id: str, claimed_at: datetime) -> bool:
        raise NotImplementedError

    async def record_event(self, document: dict[str, Any]) -> None:
        raise NotImplementedError

    async def list_events(self, limit: int = 25) -> list[dict[str, Any]]:
        raise NotImplementedError

    async def stats(self) -> dict[str, int]:
        raise NotImplementedError


class MemoryStore(BaseStore):
    """Development and test store. Production must use MongoDB."""

    def __init__(self) -> None:
        self.links: dict[str, dict[str, Any]] = {}
        self.flows: dict[str, dict[str, Any]] = {}
        self.events: list[dict[str, Any]] = []
        self._lock = asyncio.Lock()

    async def create_link(self, document: dict[str, Any]) -> None:
        async with self._lock:
            self.links[document["id"]] = deepcopy(document)

    async def get_link(self, link_id: str) -> dict[str, Any] | None:
        async with self._lock:
            value = self.links.get(link_id)
            return deepcopy(value) if value else None

    async def list_links(self, limit: int = 20) -> list[dict[str, Any]]:
        async with self._lock:
            rows = sorted(self.links.values(), key=lambda item: item["created_at"], reverse=True)
            return deepcopy(rows[:limit])

    async def create_flow(self, document: dict[str, Any]) -> None:
        async with self._lock:
            self.flows[document["id"]] = deepcopy(document)

    async def get_flow(self, flow_id: str) -> dict[str, Any] | None:
        async with self._lock:
            value = self.flows.get(flow_id)
            return deepcopy(value) if value else None

    async def activate_flow(
        self, flow_id: str, nonce_hash: str, short_url: str, activated_at: datetime
    ) -> bool:
        async with self._lock:
            flow = self.flows.get(flow_id)
            if not flow or flow["state"] != "started":
                return False
            flow.update(
                state="shortener",
                nonce_hash=nonce_hash,
                short_url=short_url,
                activated_at=activated_at,
            )
            return True

    async def consume_flow(self, flow_id: str, consumed_at: datetime) -> bool:
        async with self._lock:
            flow = self.flows.get(flow_id)
            if not flow or flow["state"] != "shortener" or flow.get("consumed_at"):
                return False
            flow["state"] = "consumed"
            flow["consumed_at"] = consumed_at
            return True

    async def increment_link(self, link_id: str, success: bool) -> None:
        async with self._lock:
            link = self.links.get(link_id)
            if not link:
                return
            field = "successful_access" if success else "blocked_access"
            link[field] = int(link.get(field, 0)) + 1

    async def claim_link_success(self, link_id: str, claimed_at: datetime) -> bool:
        async with self._lock:
            link = self.links.get(link_id)
            if (
                not link
                or not link.get("enabled", True)
                or link["expires_at"] <= claimed_at
                or int(link.get("successful_access", 0)) >= int(link.get("max_uses", 1))
            ):
                return False
            link["successful_access"] = int(link.get("successful_access", 0)) + 1
            return True

    async def record_event(self, document: dict[str, Any]) -> None:
        async with self._lock:
            self.events.append(deepcopy(document))

    async def list_events(self, limit: int = 25) -> list[dict[str, Any]]:
        async with self._lock:
            rows = sorted(self.events, key=lambda item: item["created_at"], reverse=True)
            return deepcopy(rows[:limit])

    async def stats(self) -> dict[str, int]:
        async with self._lock:
            return {
                "links_created": len(self.links),
                "successful_access": sum(int(x.get("successful_access", 0)) for x in self.links.values()),
                "blocked_access": sum(int(x.get("blocked_access", 0)) for x in self.links.values()),
                "active_flows": sum(1 for x in self.flows.values() if x.get("state") != "consumed"),
                "events": len(self.events),
            }


class MongoStore(BaseStore):
    def __init__(self, uri: str, database: str) -> None:
        from pymongo import MongoClient

        self.client = MongoClient(uri, serverSelectionTimeoutMS=5000, tz_aware=True)
        self.db = self.client[database]
        self.links = self.db.links
        self.flows = self.db.flows
        self.events = self.db.events

    async def initialize(self) -> None:
        def _setup() -> None:
            self.client.admin.command("ping")
            self.links.create_index("id", unique=True)
            self.links.create_index("expires_at")
            self.flows.create_index("id", unique=True)
            self.flows.create_index("expires_at", expireAfterSeconds=0)
            self.events.create_index("created_at")
            self.events.create_index([("link_id", 1), ("created_at", -1)])

        await asyncio.to_thread(_setup)

    async def close(self) -> None:
        await asyncio.to_thread(self.client.close)

    async def create_link(self, document: dict[str, Any]) -> None:
        await asyncio.to_thread(self.links.insert_one, deepcopy(document))

    async def get_link(self, link_id: str) -> dict[str, Any] | None:
        return await asyncio.to_thread(self.links.find_one, {"id": link_id}, {"_id": 0})

    async def list_links(self, limit: int = 20) -> list[dict[str, Any]]:
        def _read() -> list[dict[str, Any]]:
            return list(self.links.find({}, {"_id": 0}).sort("created_at", -1).limit(limit))

        return await asyncio.to_thread(_read)

    async def create_flow(self, document: dict[str, Any]) -> None:
        await asyncio.to_thread(self.flows.insert_one, deepcopy(document))

    async def get_flow(self, flow_id: str) -> dict[str, Any] | None:
        return await asyncio.to_thread(self.flows.find_one, {"id": flow_id}, {"_id": 0})

    async def activate_flow(
        self, flow_id: str, nonce_hash: str, short_url: str, activated_at: datetime
    ) -> bool:
        def _update() -> bool:
            result = self.flows.update_one(
                {"id": flow_id, "state": "started"},
                {
                    "$set": {
                        "state": "shortener",
                        "nonce_hash": nonce_hash,
                        "short_url": short_url,
                        "activated_at": activated_at,
                    }
                },
            )
            return result.modified_count == 1

        return await asyncio.to_thread(_update)

    async def consume_flow(self, flow_id: str, consumed_at: datetime) -> bool:
        def _update() -> bool:
            result = self.flows.update_one(
                {"id": flow_id, "state": "shortener", "consumed_at": None},
                {"$set": {"state": "consumed", "consumed_at": consumed_at}},
            )
            return result.modified_count == 1

        return await asyncio.to_thread(_update)

    async def increment_link(self, link_id: str, success: bool) -> None:
        field = "successful_access" if success else "blocked_access"
        await asyncio.to_thread(self.links.update_one, {"id": link_id}, {"$inc": {field: 1}})

    async def claim_link_success(self, link_id: str, claimed_at: datetime) -> bool:
        def _update() -> bool:
            result = self.links.update_one(
                {
                    "id": link_id,
                    "enabled": True,
                    "expires_at": {"$gt": claimed_at},
                    "$expr": {"$lt": ["$successful_access", "$max_uses"]},
                },
                {"$inc": {"successful_access": 1}},
            )
            return result.modified_count == 1

        return await asyncio.to_thread(_update)

    async def record_event(self, document: dict[str, Any]) -> None:
        await asyncio.to_thread(self.events.insert_one, deepcopy(document))

    async def list_events(self, limit: int = 25) -> list[dict[str, Any]]:
        def _read() -> list[dict[str, Any]]:
            return list(self.events.find({}, {"_id": 0}).sort("created_at", -1).limit(limit))

        return await asyncio.to_thread(_read)

    async def stats(self) -> dict[str, int]:
        def _read() -> dict[str, int]:
            pipeline = [
                {
                    "$group": {
                        "_id": None,
                        "successful_access": {"$sum": "$successful_access"},
                        "blocked_access": {"$sum": "$blocked_access"},
                    }
                }
            ]
            totals = next(iter(self.links.aggregate(pipeline)), {})
            return {
                "links_created": self.links.count_documents({}),
                "successful_access": int(totals.get("successful_access", 0)),
                "blocked_access": int(totals.get("blocked_access", 0)),
                "active_flows": self.flows.count_documents({"state": {"$ne": "consumed"}}),
                "events": self.events.count_documents({}),
            }

        return await asyncio.to_thread(_read)
