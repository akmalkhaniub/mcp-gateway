"""Stateless 2026-07-28 MCP protocol negotiation, HMAC opaque state handles, and Tasks routing."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from collections.abc import Mapping
from enum import StrEnum
from typing import Any

from pydantic import BaseModel

STATELESS_PROTOCOL_VERSION = "2026-07-28"
LEGACY_PROTOCOL_VERSION = "2024-11-05"


class ProtocolMode(StrEnum):
    STATELESS_2026 = "stateless_2026"
    LEGACY_2024 = "legacy_2024"


class StatelessHandleError(Exception):
    """Raised when an opaque MCP state/cursor handle fails HMAC, expiry, or principal checks."""


class VerifiedStateHandle(BaseModel):
    principal: str
    server_id: str
    cursor: str
    issued_at: int
    expires_at: int


def _b64u_enc(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_dec(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * ((4 - len(segment) % 4) % 4))


def negotiate_protocol_mode(
    headers: Mapping[str, str],
    payload: dict[str, Any] | None = None,
    default_mode: ProtocolMode | None = None,
) -> tuple[ProtocolMode, str]:
    """
    Determine effective MCP protocol mode (`stateless_2026` vs `legacy_2024`).

    Precedence:
    1. `params._meta.protocolVersion` (per-request stateless negotiation)
    2. `MCP-Protocol-Version` HTTP header
    3. `MCP_PROTOCOL_MODE` environment variable / default_mode
    """
    env_mode = os.getenv("MCP_PROTOCOL_MODE", "").strip().lower()
    fallback = default_mode or (
        ProtocolMode.STATELESS_2026 if env_mode == ProtocolMode.STATELESS_2026.value else ProtocolMode.LEGACY_2024
    )

    meta_ver = None
    if isinstance(payload, dict):
        params = payload.get("params")
        if isinstance(params, dict) and isinstance(params.get("_meta"), dict):
            raw_ver = params["_meta"].get("protocolVersion")
            if isinstance(raw_ver, str) and raw_ver.strip():
                meta_ver = raw_ver.strip()

    requested = meta_ver or headers.get("MCP-Protocol-Version", "").strip()
    if requested == STATELESS_PROTOCOL_VERSION or requested == "stateless_2026":
        return ProtocolMode.STATELESS_2026, STATELESS_PROTOCOL_VERSION
    if requested == LEGACY_PROTOCOL_VERSION or requested == "legacy_2024":
        return ProtocolMode.LEGACY_2024, LEGACY_PROTOCOL_VERSION

    version = STATELESS_PROTOCOL_VERSION if fallback == ProtocolMode.STATELESS_2026 else LEGACY_PROTOCOL_VERSION
    return fallback, version


class StatelessHandleManager:
    """
    Mints and verifies HMAC-SHA256 signed opaque routing/cursor handles for stateless multi-replica MCP.

    Enforces principal binding so a leaked or forged handle cannot be replayed by another caller.
    """

    def __init__(self, secret: str | None = None, default_ttl_seconds: int = 900) -> None:
        raw = secret or os.getenv("MCP_STATELESS_HANDLE_SECRET") or secrets.token_hex(32)
        self._secret = raw.encode("utf-8")
        self.default_ttl_seconds = default_ttl_seconds

    def mint_handle(
        self,
        *,
        principal: str,
        server_id: str,
        cursor: str,
        ttl_seconds: int | None = None,
    ) -> str:
        now = int(time.time())
        exp = now + (ttl_seconds or self.default_ttl_seconds)
        claims = {
            "sub": principal,
            "srv": server_id,
            "cur": cursor,
            "iat": now,
            "exp": exp,
        }
        payload_b64 = _b64u_enc(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode("utf-8"))
        sig = hmac.new(self._secret, payload_b64.encode("ascii"), hashlib.sha256).digest()
        return f"gwsh_{payload_b64}.{_b64u_enc(sig)}"

    def verify_handle(
        self,
        handle: str,
        *,
        expected_principal: str,
        now: float | None = None,
    ) -> VerifiedStateHandle:
        if not isinstance(handle, str) or not handle.startswith("gwsh_") or "." not in handle:
            raise StatelessHandleError("Malformed or unsigned opaque state handle.")

        body = handle[len("gwsh_") :]
        payload_b64, sig_b64 = body.split(".", 1)
        expected_sig = hmac.new(self._secret, payload_b64.encode("ascii"), hashlib.sha256).digest()
        try:
            provided_sig = _b64u_dec(sig_b64)
            claims = json.loads(_b64u_dec(payload_b64))
        except Exception as exc:
            raise StatelessHandleError(f"Corrupted state handle payload: {exc}") from exc

        if not hmac.compare_digest(provided_sig, expected_sig):
            raise StatelessHandleError("State handle HMAC signature mismatch (tampering rejected).")

        current = time.time() if now is None else now
        if current >= float(claims.get("exp", 0)):
            raise StatelessHandleError("State handle has expired.")

        if claims.get("sub") != expected_principal:
            raise StatelessHandleError(
                f"State handle principal mismatch: handle bound to '{claims.get('sub')}', caller is '{expected_principal}'."
            )

        return VerifiedStateHandle(
            principal=str(claims["sub"]),
            server_id=str(claims["srv"]),
            cursor=str(claims["cur"]),
            issued_at=int(claims["iat"]),
            expires_at=int(claims["exp"]),
        )


def parse_task_handle(task_id: str) -> tuple[str, str] | None:
    """Parse `{server_id}:{upstream_task_id}` task handles for transparent MCP Tasks forwarding."""
    if not isinstance(task_id, str) or ":" not in task_id:
        return None
    server_id, upstream_task_id = task_id.split(":", 1)
    server_id = server_id.strip()
    upstream_task_id = upstream_task_id.strip()
    if not server_id or not upstream_task_id:
        return None
    return server_id, upstream_task_id
