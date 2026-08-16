from __future__ import annotations

import json
import os
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


class KeyManager:
    """Versioned RSA key manager used to wrap per-record AES data keys."""

    def __init__(self, key_dir: Path, passphrase: str | None = None) -> None:
        self.key_dir = key_dir
        self.registry_path = key_dir / "registry.json"
        self.passphrase = passphrase.encode("utf-8") if passphrase else None
        self._lock = threading.RLock()
        self.key_dir.mkdir(parents=True, exist_ok=True)

    def ensure_initialized(self) -> None:
        with self._lock:
            if not self.registry_path.exists():
                key_id = self.create_pending_key()
                self.activate_key(key_id)

    def _load_registry(self) -> dict[str, Any]:
        if not self.registry_path.exists():
            return {"active_key_id": None, "keys": {}}
        return json.loads(self.registry_path.read_text(encoding="utf-8"))

    def _save_registry(self, registry: dict[str, Any]) -> None:
        temp = self.registry_path.with_suffix(".tmp")
        temp.write_text(json.dumps(registry, indent=2, sort_keys=True), encoding="utf-8")
        os.chmod(temp, 0o600)
        temp.replace(self.registry_path)

    def create_pending_key(self) -> str:
        with self._lock:
            key_id = f"rsa-{datetime.now(UTC):%Y%m%d%H%M%S}-{uuid.uuid4().hex[:8]}"
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
            public_key = private_key.public_key()

            private_filename = f"{key_id}-private.pem"
            public_filename = f"{key_id}-public.pem"
            private_path = self.key_dir / private_filename
            public_path = self.key_dir / public_filename

            encryption = (
                serialization.BestAvailableEncryption(self.passphrase)
                if self.passphrase
                else serialization.NoEncryption()
            )
            private_path.write_bytes(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=encryption,
                )
            )
            public_path.write_bytes(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
            os.chmod(private_path, 0o600)
            os.chmod(public_path, 0o644)

            registry = self._load_registry()
            registry["keys"][key_id] = {
                "private": private_filename,
                "public": public_filename,
                "created_at": datetime.now(UTC).isoformat(),
                "status": "pending",
            }
            self._save_registry(registry)
            return key_id

    def activate_key(self, key_id: str) -> None:
        with self._lock:
            registry = self._load_registry()
            if key_id not in registry["keys"]:
                raise KeyError(f"Unknown key id: {key_id}")
            old_key_id = registry.get("active_key_id")
            if old_key_id and old_key_id in registry["keys"]:
                registry["keys"][old_key_id]["status"] = "retired"
            registry["keys"][key_id]["status"] = "active"
            registry["active_key_id"] = key_id
            self._save_registry(registry)

    @property
    def active_key_id(self) -> str:
        self.ensure_initialized()
        registry = self._load_registry()
        key_id = registry.get("active_key_id")
        if not key_id:
            raise RuntimeError("No active RSA key is configured.")
        return str(key_id)

    def _key_paths(self, key_id: str) -> tuple[Path, Path]:
        registry = self._load_registry()
        metadata = registry.get("keys", {}).get(key_id)
        if not metadata:
            raise KeyError(f"Unknown key id: {key_id}")
        return self.key_dir / metadata["private"], self.key_dir / metadata["public"]

    def wrap_key(self, data_key: bytes, key_id: str | None = None) -> tuple[bytes, str]:
        selected_key_id = key_id or self.active_key_id
        _, public_path = self._key_paths(selected_key_id)
        public_key = serialization.load_pem_public_key(public_path.read_bytes())
        wrapped = public_key.encrypt(
            data_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return wrapped, selected_key_id

    def unwrap_key(self, wrapped_key: bytes, key_id: str) -> bytes:
        private_path, _ = self._key_paths(key_id)
        private_key = serialization.load_pem_private_key(
            private_path.read_bytes(), password=self.passphrase
        )
        return private_key.decrypt(
            wrapped_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    def rewrap_key(self, wrapped_key: bytes, source_key_id: str, target_key_id: str) -> bytes:
        data_key = self.unwrap_key(wrapped_key, source_key_id)
        rewrapped, _ = self.wrap_key(data_key, target_key_id)
        return rewrapped
