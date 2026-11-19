"""Optional API authentication and append-only audit logging.

Uses only the standard library. Auth is off by default so local development and
the smoke tests work unchanged. Set APKPT_AUTH_ENABLED=1 and change
APKPT_ADMIN_PASS / APKPT_JWT_SECRET before exposing the service.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException, Request

from . import config


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def create_token(user: str, ttl_hours: int | None = None) -> str:
    hours = config.JWT_TTL_HOURS if ttl_hours is None else ttl_hours
    payload = json.dumps(
        {"sub": user, "exp": int(time.time()) + hours * 3600, "iat": int(time.time())},
        separators=(",", ":"),
    ).encode("utf-8")
    body = _b64encode(payload)
    sig = _b64encode(hmac.new(config.JWT_SECRET.encode("utf-8"), body.encode("ascii"), hashlib.sha256).digest())
    return f"{body}.{sig}"


def verify_token(token: str) -> str | None:
    try:
        body, sig = token.split(".", 1)
        expected = _b64encode(hmac.new(config.JWT_SECRET.encode("utf-8"), body.encode("ascii"), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            return None
        payload = json.loads(_b64decode(body))
        if int(payload.get("exp", 0)) < int(time.time()):
            return None
        user = payload.get("sub")
        return str(user) if user else None
    except Exception:
        return None


def authenticate(username: str, password: str) -> str | None:
    user_ok = hmac.compare_digest(username, config.ADMIN_USER)
    pass_ok = hmac.compare_digest(password, config.ADMIN_PASS)
    return config.ADMIN_USER if user_ok and pass_ok else None


def require_auth(request: Request) -> str:
    """FastAPI dependency for write operations."""
    static = request.headers.get("x-api-key", "")
    if config.API_TOKEN and static and hmac.compare_digest(static, config.API_TOKEN):
        return "api-token"
    header = request.headers.get("authorization", "")
    token = header[7:].strip() if header.lower().startswith("bearer ") else ""
    user = verify_token(token) if token else None
    if user:
        return user
    if not config.AUTH_ENABLED:
        return "anonymous"
    raise HTTPException(401, "authentication required", headers={"WWW-Authenticate": "Bearer"})


def audit(action: str, detail: dict[str, Any] | str, actor: str = "anonymous") -> None:
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "actor": actor,
        "action": action,
        "detail": detail if isinstance(detail, str) else json.dumps(detail, ensure_ascii=False, default=str),
    }
    try:
        config.AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(config.AUDIT_LOG, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass
