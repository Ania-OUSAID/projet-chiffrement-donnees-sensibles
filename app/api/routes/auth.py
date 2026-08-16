from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select

from app.api.deps import CurrentUser, DbSession
from app.audit import add_audit_log
from app.config import get_settings
from app.models import User
from app.schemas import Token, UserCreate, UserMe
from app.security.passwords import hash_password, verify_password
from app.security.rate_limit import RateLimitExceeded
from app.security.tokens import create_access_token
from app.state import crypto_service, login_limiter

router = APIRouter(prefix="/auth", tags=["Authentification"])


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


@router.post("/register", response_model=UserMe, status_code=status.HTTP_201_CREATED)
def register(payload: UserCreate, request: Request, db: DbSession) -> UserMe:
    if db.scalar(select(User).where(User.username == payload.username)):
        raise HTTPException(status_code=409, detail="Ce nom d'utilisateur est déjà utilisé.")

    aad = f"user-email:{payload.username}".encode()
    encrypted_email = crypto_service.encrypt(payload.email.encode("utf-8"), aad)
    user = User(
        username=payload.username,
        hashed_password=hash_password(payload.password),
        email_ciphertext=encrypted_email.ciphertext,
        email_nonce=encrypted_email.nonce,
        email_wrapped_key=encrypted_email.wrapped_key,
        email_key_id=encrypted_email.key_id,
    )
    db.add(user)
    db.flush()
    add_audit_log(
        db,
        event_type="USER_REGISTERED",
        outcome="success",
        actor_user_id=user.id,
        ip_address=_client_ip(request),
    )
    db.commit()
    db.refresh(user)
    return UserMe(
        id=user.id,
        username=user.username,
        email=payload.email,
        role=user.role,
        is_active=user.is_active,
        created_at=user.created_at,
    )


@router.post("/token", response_model=Token)
def login(
    request: Request,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: DbSession,
) -> Token:
    ip = _client_ip(request)
    limiter_key = f"{ip}:{form_data.username.lower()}"
    try:
        login_limiter.check(limiter_key)
    except RateLimitExceeded as exc:
        retry_after = str(exc)
        add_audit_log(
            db,
            event_type="LOGIN_RATE_LIMITED",
            outcome="blocked",
            ip_address=ip,
            details={"username": form_data.username, "retry_after": retry_after},
        )
        db.commit()
        raise HTTPException(
            status_code=429,
            detail="Trop de tentatives. Réessayez plus tard.",
            headers={"Retry-After": retry_after},
        ) from exc

    user = db.scalar(select(User).where(User.username == form_data.username))
    if not user or not verify_password(form_data.password, user.hashed_password):
        login_limiter.register_failure(limiter_key)
        add_audit_log(
            db,
            event_type="LOGIN_FAILED",
            outcome="failure",
            actor_user_id=user.id if user else None,
            ip_address=ip,
            details={"username": form_data.username},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Identifiants incorrects.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Compte désactivé.")

    login_limiter.register_success(limiter_key)
    token = create_access_token(user.username, user.role)
    add_audit_log(
        db,
        event_type="LOGIN_SUCCESS",
        outcome="success",
        actor_user_id=user.id,
        ip_address=ip,
    )
    db.commit()
    settings = get_settings()
    return Token(
        access_token=token,
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.get("/me", response_model=UserMe)
def read_me(current_user: CurrentUser) -> UserMe:
    aad = f"user-email:{current_user.username}".encode()
    email = crypto_service.decrypt(
        current_user.email_ciphertext,
        current_user.email_nonce,
        current_user.email_wrapped_key,
        current_user.email_key_id,
        aad,
    ).decode("utf-8")
    return UserMe(
        id=current_user.id,
        username=current_user.username,
        email=email,
        role=current_user.role,
        is_active=current_user.is_active,
        created_at=current_user.created_at,
    )
