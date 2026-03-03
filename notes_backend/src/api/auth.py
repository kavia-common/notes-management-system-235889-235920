import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional
from uuid import UUID

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from passlib.context import CryptContext

from src.api.db import db_cursor

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer_scheme = HTTPBearer(auto_error=False)


def _jwt_secret() -> str:
    # Prefer explicit secret if provided; otherwise use a dev fallback.
    # NOTE: Orchestrator should set JWT_SECRET in production.
    return os.getenv("JWT_SECRET", "dev-insecure-change-me")


def _jwt_issuer() -> str:
    return os.getenv("JWT_ISSUER", "notes-backend")


def _jwt_audience() -> Optional[str]:
    # Optional: if set, we validate aud claim.
    return os.getenv("JWT_AUDIENCE")


def _token_ttl_minutes() -> int:
    try:
        return int(os.getenv("ACCESS_TOKEN_TTL_MINUTES", "120"))
    except ValueError:
        return 120


# PUBLIC_INTERFACE
def hash_password(password: str) -> str:
    """Hash a plaintext password using bcrypt."""
    return pwd_context.hash(password)


# PUBLIC_INTERFACE
def verify_password(plain_password: str, password_hash: str) -> bool:
    """Verify a plaintext password against a stored hash."""
    return pwd_context.verify(plain_password, password_hash)


# PUBLIC_INTERFACE
def create_access_token(*, user_id: UUID, email: str) -> str:
    """
    Create a signed JWT access token.

    Payload contains:
      - sub: user_id (UUID string)
      - email
      - iat/exp
      - iss (+ optional aud)
    """
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=_token_ttl_minutes())

    payload: Dict[str, Any] = {
        "sub": str(user_id),
        "email": email,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "iss": _jwt_issuer(),
    }
    aud = _jwt_audience()
    if aud:
        payload["aud"] = aud

    token = jwt.encode(payload, _jwt_secret(), algorithm="HS256")
    return token


def _decode_token(token: str) -> Dict[str, Any]:
    options = {"require": ["exp", "iat", "iss", "sub"]}
    kwargs: Dict[str, Any] = {
        "key": _jwt_secret(),
        "algorithms": ["HS256"],
        "options": options,
        "issuer": _jwt_issuer(),
    }
    aud = _jwt_audience()
    if aud:
        kwargs["audience"] = aud

    return jwt.decode(token, **kwargs)


def _get_user_by_id(user_id: UUID) -> Optional[dict]:
    with next(db_cursor()) as cur:
        cur.execute(
            """
            SELECT id, email, created_at, updated_at, last_login_at
            FROM users
            WHERE id = %s
            """,
            (str(user_id),),
        )
        return cur.fetchone()


# PUBLIC_INTERFACE
def get_current_user(
    creds: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> dict:
    """
    FastAPI dependency to authenticate requests via Authorization: Bearer <token>.

    Returns:
        dict: user row

    Raises:
        HTTPException(401): if missing/invalid token or user not found.
    """
    if creds is None or not creds.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
        )

    try:
        payload = _decode_token(creds.credentials)
        user_id = UUID(payload["sub"])
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )

    user = _get_user_by_id(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )
    return user
