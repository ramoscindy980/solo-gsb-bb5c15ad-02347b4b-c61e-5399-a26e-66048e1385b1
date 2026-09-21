"""Pydantic request/response models."""
from __future__ import annotations

from pydantic import BaseModel, Field, model_validator


class FragmentIn(BaseModel):
    start: int = Field(ge=0, description="Unicode code-point offset, inclusive")
    end: int = Field(ge=1, description="Unicode code-point offset, exclusive")
    category: str = Field(default="SENSITIVE", max_length=64)
    priority: int = Field(default=0, description="higher wins on overlap")

    @model_validator(mode="after")
    def _check_span(self) -> "FragmentIn":
        if self.start >= self.end:
            raise ValueError("start must be smaller than end")
        return self


class RedactionRequest(BaseModel):
    text: str = Field(min_length=1)
    fragments: list[FragmentIn] = Field(default_factory=list)
    mapping_ttl_seconds: int | None = Field(
        default=None, ge=1, description="mapping expiry; null = server default"
    )
    token_ttl_seconds: int | None = Field(
        default=None, ge=1, description="restore-token expiry; null = server default"
    )


class FragmentDetail(BaseModel):
    placeholder: str
    category: str
    start: int
    end: int
    redacted_start: int
    redacted_end: int
    priority: int
    expires_at: str | None
    expired: bool


class DroppedDetail(BaseModel):
    start: int
    end: int
    category: str
    priority: int
    reason: str


class RedactionResponse(BaseModel):
    document_id: str
    created_at: str
    redacted_text: str
    fragments: list[FragmentDetail]
    dropped: list[DroppedDetail]
    restore_token: str = Field(description="one-time token, shown only once")
    restore_token_expires_at: str | None


class RedactionQueryResponse(BaseModel):
    document_id: str
    created_at: str
    redacted_text: str
    fragments: list[FragmentDetail]
    dropped: list[DroppedDetail]


class RestoreRequest(BaseModel):
    token: str = Field(min_length=1)
    placeholders: list[str] = Field(min_length=1)


class RestoredItem(BaseModel):
    placeholder: str
    category: str
    text: str


class RestoreResponse(BaseModel):
    document_id: str
    restored_text: str
    restored: list[RestoredItem]
