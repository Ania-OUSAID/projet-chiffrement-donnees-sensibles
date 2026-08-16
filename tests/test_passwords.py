import pytest

bcrypt = pytest.importorskip("bcrypt")

from app.security.passwords import hash_password, verify_password  # noqa: E402


def test_password_hash_and_verify() -> None:
    password_hash = hash_password("A-strong-password-2026")
    assert password_hash != "A-strong-password-2026"
    assert verify_password("A-strong-password-2026", password_hash)
    assert not verify_password("wrong-password-2026", password_hash)


def test_password_byte_limit() -> None:
    with pytest.raises(ValueError):
        hash_password("é" * 40)
