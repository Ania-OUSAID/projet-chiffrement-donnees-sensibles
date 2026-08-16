from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.security.keys import KeyManager


@dataclass(frozen=True)
class EncryptedPayload:
    ciphertext: bytes
    nonce: bytes
    wrapped_key: bytes
    key_id: str


class EnvelopeCrypto:
    """AES-256-GCM for data; RSA-OAEP for wrapping the one-time AES key."""

    def __init__(self, key_manager: KeyManager) -> None:
        self.key_manager = key_manager

    def encrypt(self, plaintext: bytes, associated_data: bytes) -> EncryptedPayload:
        data_key = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(12)
        ciphertext = AESGCM(data_key).encrypt(nonce, plaintext, associated_data)
        wrapped_key, key_id = self.key_manager.wrap_key(data_key)
        return EncryptedPayload(ciphertext, nonce, wrapped_key, key_id)

    def decrypt(
        self,
        ciphertext: bytes,
        nonce: bytes,
        wrapped_key: bytes,
        key_id: str,
        associated_data: bytes,
    ) -> bytes:
        data_key = self.key_manager.unwrap_key(wrapped_key, key_id)
        return AESGCM(data_key).decrypt(nonce, ciphertext, associated_data)

    def rewrap(self, wrapped_key: bytes, source_key_id: str, target_key_id: str) -> bytes:
        return self.key_manager.rewrap_key(wrapped_key, source_key_id, target_key_id)
