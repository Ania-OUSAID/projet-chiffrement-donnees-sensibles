from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    app_name: str
    environment: str
    database_url: str
    jwt_secret: str
    jwt_algorithm: str
    access_token_expire_minutes: int
    key_dir: Path
    key_passphrase: str | None
    bcrypt_rounds: int
    max_login_attempts: int
    login_window_seconds: int
    allowed_hosts: tuple[str, ...]

    @property
    def is_production(self) -> bool:
        return self.environment.lower() == "production"

    def validate(self) -> None:
        if self.is_production and len(self.jwt_secret) < 32:
            raise RuntimeError("JWT_SECRET must contain at least 32 characters in production.")
        if self.is_production and not self.key_passphrase:
            raise RuntimeError("KEY_PASSPHRASE is required in production.")
        if not 10 <= self.bcrypt_rounds <= 16:
            raise RuntimeError("BCRYPT_ROUNDS must be between 10 and 16.")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    settings = Settings(
        app_name=os.getenv("APP_NAME", "Coffre-fort de données sensibles"),
        environment=os.getenv("ENVIRONMENT", "development"),
        database_url=os.getenv("DATABASE_URL", "sqlite:///./data/secure_vault.db"),
        jwt_secret=os.getenv("JWT_SECRET", "development-only-change-me-immediately"),
        jwt_algorithm=os.getenv("JWT_ALGORITHM", "HS256"),
        access_token_expire_minutes=int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30")),
        key_dir=Path(os.getenv("KEY_DIR", "./keys")),
        key_passphrase=os.getenv("KEY_PASSPHRASE") or None,
        bcrypt_rounds=int(os.getenv("BCRYPT_ROUNDS", "12")),
        max_login_attempts=int(os.getenv("MAX_LOGIN_ATTEMPTS", "5")),
        login_window_seconds=int(os.getenv("LOGIN_WINDOW_SECONDS", "900")),
        allowed_hosts=tuple(
            host.strip()
            for host in os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1,testserver").split(",")
            if host.strip()
        ),
    )
    settings.validate()
    return settings
