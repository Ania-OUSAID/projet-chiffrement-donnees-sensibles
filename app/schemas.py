from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    email: str = Field(min_length=5, max_length=254)
    password: str = Field(min_length=12, max_length=72)

    @field_validator("password")
    @classmethod
    def password_must_fit_bcrypt(cls, value: str) -> str:
        if len(value.encode("utf-8")) > 72:
            raise ValueError("Le mot de passe ne doit pas dépasser 72 octets UTF-8 avec bcrypt.")
        return value


class UserMe(BaseModel):
    id: int
    username: str
    email: str
    role: str
    is_active: bool
    created_at: datetime


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class RecordCreate(BaseModel):
    data_type: str = Field(min_length=2, max_length=50, pattern=r"^[A-Za-z0-9_.-]+$")
    payload: dict[str, Any]


class RecordUpdate(BaseModel):
    data_type: str | None = Field(default=None, min_length=2, max_length=50)
    payload: dict[str, Any]


class RecordMetadata(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    data_type: str
    created_at: datetime
    updated_at: datetime


class RecordOut(RecordMetadata):
    payload: dict[str, Any]


class AuditLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    event_type: str
    outcome: str
    actor_user_id: int | None
    ip_address: str | None
    details_json: str


class KeyRotationResult(BaseModel):
    new_key_id: str
    users_rewrapped: int
    records_rewrapped: int
    status: str
