from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.api.routes import admin, auth, vault
from app.config import get_settings
from app.database import init_db
from app.middleware import SecurityHeadersMiddleware
from app.state import key_manager

settings = get_settings()


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    key_manager.ensure_initialized()
    yield


app = FastAPI(
    title=settings.app_name,
    version="1.0.0",
    description="API pédagogique de protection des données sensibles par bcrypt, AES-GCM et RSA-OAEP.",
    lifespan=lifespan,
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(settings.allowed_hosts))
app.add_middleware(SecurityHeadersMiddleware)
app.include_router(auth.router)
app.include_router(vault.router)
app.include_router(admin.router)


@app.get("/health", tags=["Système"])
def health() -> dict[str, str]:
    return {"status": "ok"}
