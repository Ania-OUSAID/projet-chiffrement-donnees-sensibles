from __future__ import annotations

import argparse
import getpass

from sqlalchemy import select

from app.database import SessionLocal, init_db
from app.models import User
from app.security.passwords import hash_password
from app.state import crypto_service, key_manager


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a local administrator account.")
    parser.add_argument("username")
    parser.add_argument("email")
    args = parser.parse_args()
    password = getpass.getpass("Admin password (12-72 UTF-8 bytes): ")

    init_db()
    key_manager.ensure_initialized()
    with SessionLocal() as db:
        if db.scalar(select(User).where(User.username == args.username)):
            raise SystemExit("Username already exists.")
        encrypted = crypto_service.encrypt(
            args.email.encode(), f"user-email:{args.username}".encode()
        )
        user = User(
            username=args.username,
            hashed_password=hash_password(password),
            role="admin",
            email_ciphertext=encrypted.ciphertext,
            email_nonce=encrypted.nonce,
            email_wrapped_key=encrypted.wrapped_key,
            email_key_id=encrypted.key_id,
        )
        db.add(user)
        db.commit()
        print(f"Administrator '{args.username}' created.")


if __name__ == "__main__":
    main()
