from __future__ import annotations

import json
import uuid

from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import select

from app.api.deps import CurrentUser, DbSession
from app.audit import add_audit_log
from app.models import SensitiveRecord
from app.schemas import RecordCreate, RecordMetadata, RecordOut, RecordUpdate
from app.state import crypto_service

router = APIRouter(prefix="/vault", tags=["Coffre-fort"])


def _aad(record_id: str, owner_id: int, data_type: str) -> bytes:
    return f"record:{record_id}:{owner_id}:{data_type}".encode()


def _serialize(payload: dict[str, object]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


@router.post("", response_model=RecordOut, status_code=status.HTTP_201_CREATED)
def create_record(
    payload: RecordCreate, request: Request, current_user: CurrentUser, db: DbSession
) -> RecordOut:
    record_id = str(uuid.uuid4())
    encrypted = crypto_service.encrypt(
        _serialize(payload.payload), _aad(record_id, current_user.id, payload.data_type)
    )
    record = SensitiveRecord(
        id=record_id,
        owner_id=current_user.id,
        data_type=payload.data_type,
        ciphertext=encrypted.ciphertext,
        nonce=encrypted.nonce,
        wrapped_key=encrypted.wrapped_key,
        key_id=encrypted.key_id,
    )
    db.add(record)
    add_audit_log(
        db,
        event_type="RECORD_CREATED",
        outcome="success",
        actor_user_id=current_user.id,
        ip_address=_client_ip(request),
        details={"record_id": record_id, "data_type": payload.data_type},
    )
    db.commit()
    db.refresh(record)
    return RecordOut(
        id=record.id,
        data_type=record.data_type,
        payload=payload.payload,
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


@router.get("", response_model=list[RecordMetadata])
def list_records(current_user: CurrentUser, db: DbSession) -> list[SensitiveRecord]:
    return list(
        db.scalars(
            select(SensitiveRecord)
            .where(SensitiveRecord.owner_id == current_user.id)
            .order_by(SensitiveRecord.created_at.desc())
        ).all()
    )


def _owned_record(record_id: str, user_id: int, db: DbSession) -> SensitiveRecord:
    record = db.scalar(
        select(SensitiveRecord).where(
            SensitiveRecord.id == record_id, SensitiveRecord.owner_id == user_id
        )
    )
    if not record:
        raise HTTPException(status_code=404, detail="Enregistrement introuvable.")
    return record


@router.get("/{record_id}", response_model=RecordOut)
def get_record(
    record_id: str, request: Request, current_user: CurrentUser, db: DbSession
) -> RecordOut:
    record = _owned_record(record_id, current_user.id, db)
    plaintext = crypto_service.decrypt(
        record.ciphertext,
        record.nonce,
        record.wrapped_key,
        record.key_id,
        _aad(record.id, record.owner_id, record.data_type),
    )
    add_audit_log(
        db,
        event_type="RECORD_READ",
        outcome="success",
        actor_user_id=current_user.id,
        ip_address=_client_ip(request),
        details={"record_id": record.id, "data_type": record.data_type},
    )
    db.commit()
    return RecordOut(
        id=record.id,
        data_type=record.data_type,
        payload=json.loads(plaintext),
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


@router.put("/{record_id}", response_model=RecordOut)
def update_record(
    record_id: str,
    payload: RecordUpdate,
    request: Request,
    current_user: CurrentUser,
    db: DbSession,
) -> RecordOut:
    record = _owned_record(record_id, current_user.id, db)
    data_type = payload.data_type or record.data_type
    encrypted = crypto_service.encrypt(
        _serialize(payload.payload), _aad(record.id, record.owner_id, data_type)
    )
    record.data_type = data_type
    record.ciphertext = encrypted.ciphertext
    record.nonce = encrypted.nonce
    record.wrapped_key = encrypted.wrapped_key
    record.key_id = encrypted.key_id
    add_audit_log(
        db,
        event_type="RECORD_UPDATED",
        outcome="success",
        actor_user_id=current_user.id,
        ip_address=_client_ip(request),
        details={"record_id": record.id, "data_type": data_type},
    )
    db.commit()
    db.refresh(record)
    return RecordOut(
        id=record.id,
        data_type=record.data_type,
        payload=payload.payload,
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


@router.delete("/{record_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_record(
    record_id: str, request: Request, current_user: CurrentUser, db: DbSession
) -> None:
    record = _owned_record(record_id, current_user.id, db)
    db.delete(record)
    add_audit_log(
        db,
        event_type="RECORD_DELETED",
        outcome="success",
        actor_user_id=current_user.id,
        ip_address=_client_ip(request),
        details={"record_id": record.id, "data_type": record.data_type},
    )
    db.commit()
