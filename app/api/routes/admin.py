from __future__ import annotations

from fastapi import APIRouter, Query, Request
from sqlalchemy import select

from app.api.deps import AdminUser, DbSession
from app.audit import add_audit_log
from app.models import AuditLog
from app.schemas import AuditLogOut, KeyRotationResult
from app.services.rotation import rotate_rsa_wrapping_key

router = APIRouter(prefix="/admin", tags=["Administration"])


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


@router.post("/keys/rotate", response_model=KeyRotationResult)
def rotate_keys(request: Request, admin: AdminUser, db: DbSession) -> KeyRotationResult:
    stats = rotate_rsa_wrapping_key(db)
    add_audit_log(
        db,
        event_type="KEY_ROTATED",
        outcome="success",
        actor_user_id=admin.id,
        ip_address=_client_ip(request),
        details={
            "new_key_id": stats.new_key_id,
            "users_rewrapped": stats.users_rewrapped,
            "records_rewrapped": stats.records_rewrapped,
        },
    )
    db.commit()
    return KeyRotationResult(
        new_key_id=stats.new_key_id,
        users_rewrapped=stats.users_rewrapped,
        records_rewrapped=stats.records_rewrapped,
        status="active",
    )


@router.get("/audit-logs", response_model=list[AuditLogOut])
def audit_logs(
    admin: AdminUser,
    db: DbSession,
    limit: int = Query(default=100, ge=1, le=500),
) -> list[AuditLog]:
    del admin
    return list(db.scalars(select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit)).all())
