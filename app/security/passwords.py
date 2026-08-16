from __future__ import annotations

try:
    import bcrypt
except ImportError as exc:  # pragma: no cover - explicit installation error
    raise RuntimeError(
        "The 'bcrypt' package is required. Install dependencies with: pip install -r requirements.txt"
    ) from exc

from app.config import get_settings


def _validate_password(password: str) -> bytes:
    encoded = password.encode("utf-8")
    if len(encoded) < 12:
        raise ValueError("Password must contain at least 12 UTF-8 bytes.")
    if len(encoded) > 72:
        raise ValueError("bcrypt accepts at most 72 input bytes.")
    return encoded


def hash_password(password: str) -> str:
    encoded = _validate_password(password)
    rounds = get_settings().bcrypt_rounds
    return bcrypt.hashpw(encoded, bcrypt.gensalt(rounds=rounds)).decode("ascii")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        encoded = _validate_password(password)
        return bcrypt.checkpw(encoded, password_hash.encode("ascii"))
    except (ValueError, TypeError):
        return False
