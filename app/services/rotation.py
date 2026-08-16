from __future__ import annotations

import threading
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import SensitiveRecord, User
from app.state import crypto_service, key_manager


@dataclass(frozen=True)
class RotationStats:
    new_key_id: str
    users_rewrapped: int
    records_rewrapped: int


_rotation_lock = threading.Lock()


def rotate_rsa_wrapping_key(db: Session) -> RotationStats:
    """Rewrap all AES data keys and then activate the new RSA version.

    The process-level lock prevents two rotations from running concurrently in the
    educational single-instance deployment. A distributed production deployment
    should use a database or orchestration lock.
    """
    with _rotation_lock:
        new_key_id = key_manager.create_pending_key()
        users_count = 0
        records_count = 0

        try:
            for user in db.scalars(select(User)).all():
                user.email_wrapped_key = crypto_service.rewrap(
                    user.email_wrapped_key, user.email_key_id, new_key_id
                )
                user.email_key_id = new_key_id
                users_count += 1

            for record in db.scalars(select(SensitiveRecord)).all():
                record.wrapped_key = crypto_service.rewrap(
                    record.wrapped_key, record.key_id, new_key_id
                )
                record.key_id = new_key_id
                records_count += 1

            db.commit()
            key_manager.activate_key(new_key_id)
        except Exception:
            db.rollback()
            raise

        return RotationStats(new_key_id, users_count, records_count)
