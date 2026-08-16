from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, LargeBinary, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(20), default="user", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    email_ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    email_nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    email_wrapped_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    email_key_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    records: Mapped[list[SensitiveRecord]] = relationship(
        back_populates="owner", cascade="all, delete-orphan"
    )


class SensitiveRecord(Base):
    __tablename__ = "sensitive_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    data_type: Mapped[str] = mapped_column(String(50), nullable=False)

    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    wrapped_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    key_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    owner: Mapped[User] = relationship(back_populates="records")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    event_type: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    outcome: Mapped[str] = mapped_column(String(20), nullable=False)
    actor_user_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    details_json: Mapped[str] = mapped_column(Text, default="{}", nullable=False)
