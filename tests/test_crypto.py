from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

from app.security.crypto import EnvelopeCrypto
from app.security.keys import KeyManager


def test_encrypt_decrypt_and_rewrap(tmp_path: Path) -> None:
    manager = KeyManager(tmp_path / "keys", "test-passphrase")
    manager.ensure_initialized()
    crypto = EnvelopeCrypto(manager)

    aad = b"record:test"
    encrypted = crypto.encrypt(b"very sensitive", aad)
    assert (
        crypto.decrypt(
            encrypted.ciphertext,
            encrypted.nonce,
            encrypted.wrapped_key,
            encrypted.key_id,
            aad,
        )
        == b"very sensitive"
    )

    new_key_id = manager.create_pending_key()
    rewrapped = crypto.rewrap(encrypted.wrapped_key, encrypted.key_id, new_key_id)
    manager.activate_key(new_key_id)
    assert (
        crypto.decrypt(encrypted.ciphertext, encrypted.nonce, rewrapped, new_key_id, aad)
        == b"very sensitive"
    )


def test_tampering_is_detected(tmp_path: Path) -> None:
    manager = KeyManager(tmp_path / "keys", "test-passphrase")
    manager.ensure_initialized()
    crypto = EnvelopeCrypto(manager)
    encrypted = crypto.encrypt(b"secret", b"aad")
    tampered = bytearray(encrypted.ciphertext)
    tampered[0] ^= 1
    with pytest.raises(InvalidTag):
        crypto.decrypt(
            bytes(tampered), encrypted.nonce, encrypted.wrapped_key, encrypted.key_id, b"aad"
        )
