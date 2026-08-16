from __future__ import annotations

import json
from typing import Any

from sqlalchemy.orm import Session

from app.models import AuditLog


SENSITIVE_KEYS = {"password", "token", "secret", "payload", "ciphertext", "wrapped_key"}


def _sanitize(details: dict[str, Any] | None) -> dict[str, Any]:
    if not details:
        return {}
    return {
        key: ("[REDACTED]" if key.lower() in SENSITIVE_KEYS else value)
        for key, value in details.items()
    }


def add_audit_log(
    db: Session,
    *,
    event_type: str,
    outcome: str,
    actor_user_id: int | None = None,
    ip_address: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    db.add(
        AuditLog(
            event_type=event_type,
            outcome=outcome,
            actor_user_id=actor_user_id,
            ip_address=ip_address,
            details_json=json.dumps(_sanitize(details), ensure_ascii=False, sort_keys=True),
        )
    )
