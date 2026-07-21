from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ContinueFlowRequest(BaseModel):
    challenge: str = Field(min_length=20, max_length=2000)


class CreateLinkRequest(BaseModel):
    target_url: str = Field(min_length=4, max_length=4096)
    user_id: int | None = None
    expires_in: int | None = Field(default=None, ge=60, le=31_536_000)
    max_uses: int = Field(default=1, ge=1, le=100_000)
    metadata: dict[str, Any] = Field(default_factory=dict)


class CreateLinkResponse(BaseModel):
    id: str
    protected_url: str
    expires_at: str
    max_uses: int


class LinkStatusResponse(BaseModel):
    id: str
    enabled: bool
    expires_at: str
    max_uses: int
    successful_access: int
    blocked_access: int
    user_id: int | None = None
