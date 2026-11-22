"""OAuth 2.1 Resource Server (RFC 9728), JWT Audience Guard, and RFC 8693 Token Exchange for MCP Gateway."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from fastapi import Request
from pydantic import BaseModel, Field


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * ((4 - len(segment) % 4) % 4)
    return base64.urlsafe_b64decode(segment + padding)


class AuthChallengeError(Exception):
    """Raised when an incoming MCP request fails OAuth 2.1 Bearer verification."""

    def __init__(self, status_code: int, error: str, description: str, required_scope: str = "mcp:read") -> None:
        super().__init__(description)
        self.status_code = status_code
        self.error = error
        self.description = description
        self.required_scope = required_scope


class VerifiedPrincipal(BaseModel):
    """Cryptographically verified (or dev-fallback) caller identity extracted by the Resource Server."""

    principal: str
    client_id: str = "anonymous-client"
    scopes: list[str] = Field(default_factory=list)
    roles: list[str] = Field(default_factory=list)
    auth_method: str = "header_fallback"
    audience: str | None = None
    subject_token: str | None = None

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes or "mcp:admin" in self.scopes


@dataclass(slots=True)
class GatewayOAuthSettings:
    """Configuration for RFC 9728 Protected Resource Metadata and OAuth 2.1 JWT validation."""

    resource: str = field(
        default_factory=lambda: os.getenv("MCP_GATEWAY_RESOURCE", "https://mcp-gateway.local/mcp")
    )
    authorization_servers: list[str] = field(
        default_factory=lambda: [
            s.strip()
            for s in os.getenv("MCP_AUTHORIZATION_SERVERS", "https://auth.mcp-gateway.local").split(",")
            if s.strip()
        ]
    )
    scopes_supported: list[str] = field(
        default_factory=lambda: ["mcp:read", "mcp:write", "mcp:tasks", "mcp:admin"]
    )
    auth_mode: str = field(default_factory=lambda: os.getenv("MCP_AUTH_MODE", "optional").lower())
    jwt_secret: str = field(
        default_factory=lambda: os.getenv("MCP_OAUTH_JWT_SECRET") or secrets.token_hex(32)
    )
    expected_issuer: str | None = field(default_factory=lambda: os.getenv("MCP_OAUTH_ISSUER"))
    allow_legacy_principal_header: bool = field(
        default_factory=lambda: os.getenv("MCP_ALLOW_HEADER_PRINCIPAL", "true").lower() == "true"
    )


def mint_hs256_jwt(claims: dict[str, Any], secret: str) -> str:
    """Mint a compact HS256 JWT for Resource Server testing and RFC 8693 downstream delegation."""
    header = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode("utf-8"))
    payload = _b64url_encode(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signing_input = f"{header}.{payload}".encode("ascii")
    sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    return f"{header}.{payload}.{_b64url_encode(sig)}"


def verify_hs256_jwt(
    token: str,
    secret: str,
    *,
    expected_audience: str,
    expected_issuer: str | None = None,
    now: float | None = None,
) -> dict[str, Any]:
    """Verify HS256 signature, exp/nbf, optional iss, and strict RFC 8707 aud matching."""
    parts = token.split(".")
    if len(parts) != 3:
        raise AuthChallengeError(401, "invalid_token", "Malformed JWT structure.")

    header_b64, payload_b64, sig_b64 = parts
    try:
        header = json.loads(_b64url_decode(header_b64))
        claims = json.loads(_b64url_decode(payload_b64))
        provided_sig = _b64url_decode(sig_b64)
    except Exception as exc:
        raise AuthChallengeError(401, "invalid_token", f"Unparseable JWT encoding: {exc}") from exc

    if header.get("alg") != "HS256":
        raise AuthChallengeError(401, "invalid_token", "Unsupported JWT signing algorithm.")

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    expected_sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(provided_sig, expected_sig):
        raise AuthChallengeError(401, "invalid_token", "JWT signature verification failed.")

    current = time.time() if now is None else now
    exp = claims.get("exp")
    if not isinstance(exp, (int, float)) or current >= float(exp):
        raise AuthChallengeError(401, "invalid_token", "Bearer token has expired.")

    nbf = claims.get("nbf")
    if isinstance(nbf, (int, float)) and current < float(nbf):
        raise AuthChallengeError(401, "invalid_token", "Bearer token is not yet valid (nbf).")

    if expected_issuer and claims.get("iss") != expected_issuer:
        raise AuthChallengeError(401, "invalid_token", "JWT issuer mismatch.")

    aud = claims.get("aud")
    aud_list = [aud] if isinstance(aud, str) else (aud if isinstance(aud, list) else [])
    if expected_audience not in aud_list:
        raise AuthChallengeError(
            401,
            "invalid_token",
            f"Token passthrough rejected: JWT aud {aud_list!r} does not match resource '{expected_audience}'.",
        )

    sub = claims.get("sub")
    if not isinstance(sub, str) or not sub.strip():
        raise AuthChallengeError(401, "invalid_token", "JWT missing non-empty 'sub' claim.")

    return claims


def build_protected_resource_metadata(settings: GatewayOAuthSettings, base_url: str | None = None) -> dict[str, Any]:
    """Return RFC 9728 OAuth 2.0 Protected Resource Metadata document."""
    resource = settings.resource or (f"{base_url.rstrip('/')}/mcp" if base_url else "https://mcp-gateway.local/mcp")
    return {
        "resource": resource,
        "authorization_servers": settings.authorization_servers,
        "scopes_supported": settings.scopes_supported,
        "bearer_methods_supported": ["header"],
        "resource_name": "MCP Gateway & Reverse Proxy",
        "token_exchange_grant_types_supported": ["urn:ietf:params:oauth:grant-type:token-exchange"],
    }


def build_www_authenticate_header(
    request: Request,
    settings: GatewayOAuthSettings,
    *,
    error: str | None = None,
    description: str | None = None,
    scope: str = "mcp:read",
) -> str:
    """Build RFC 9728 WWW-Authenticate Bearer challenge pointing to /.well-known/oauth-protected-resource."""
    base = str(request.base_url).rstrip("/")
    metadata_url = f"{base}/.well-known/oauth-protected-resource"
    parts = [f'Bearer resource_metadata="{metadata_url}"', f'scope="{scope}"']
    if error:
        parts.append(f'error="{error}"')
    if description:
        safe_desc = description.replace('"', "'")
        parts.append(f'error_description="{safe_desc}"')
    return ", ".join(parts)


def authenticate_mcp_request(request: Request, settings: GatewayOAuthSettings) -> VerifiedPrincipal:
    """
    Authenticate an incoming MCP request.

    - If Authorization: Bearer <jwt> is present, always verify cryptographically (rejecting invalid/wrong-aud tokens).
    - If missing and MCP_AUTH_MODE == 'enforced', raise AuthChallengeError (401 + RFC 9728 WWW-Authenticate).
    - Otherwise fall back to X-Agent-Principal header when allowed (dev/backward-compat mode).
    """
    auth_header = request.headers.get("Authorization", "").strip()
    if auth_header:
        if not auth_header.lower().startswith("bearer "):
            raise AuthChallengeError(401, "invalid_request", "Authorization header must use Bearer scheme.")
        token = auth_header[7:].strip()
        if not token:
            raise AuthChallengeError(401, "invalid_token", "Empty Bearer token.")
        claims = verify_hs256_jwt(
            token,
            settings.jwt_secret,
            expected_audience=settings.resource,
            expected_issuer=settings.expected_issuer,
        )
        raw_scope = claims.get("scope", "")
        scopes = raw_scope.split() if isinstance(raw_scope, str) else list(raw_scope or [])
        roles = list(claims.get("roles", [])) if isinstance(claims.get("roles"), list) else []
        return VerifiedPrincipal(
            principal=str(claims["sub"]).strip(),
            client_id=str(claims.get("client_id") or claims.get("azp") or claims["sub"]),
            scopes=scopes,
            roles=roles,
            auth_method="oauth2_bearer_jwt",
            audience=settings.resource,
            subject_token=token,
        )

    if settings.auth_mode == "enforced":
        raise AuthChallengeError(401, "unauthorized", "Bearer access token required by MCP Resource Server.")

    principal = "anonymous"
    if settings.allow_legacy_principal_header:
        principal = request.headers.get("X-Agent-Principal", "anonymous").strip() or "anonymous"

    return VerifiedPrincipal(
        principal=principal,
        client_id=principal,
        scopes=[],
        roles=[],
        auth_method="header_fallback",
    )


def is_scope_sufficient(
    caller: VerifiedPrincipal,
    annotations: dict[str, Any] | None,
    tool_name: str,
) -> bool:
    """
    Enforce least-privilege OAuth scope checks when the caller authenticated with a scoped JWT.

    - Unscoped dev-fallback principals pass through to policy engine rules.
    - OAuth JWTs with empty scopes are denied; otherwise require `mcp:admin`,
      `tool:<name>`, `mcp:write` (for non-readOnly tools), or `mcp:read` (for readOnlyHint=True).
    """
    if caller.auth_method != "oauth2_bearer_jwt":
        return True
    if not caller.scopes:
        return False
    if "mcp:admin" in caller.scopes or f"tool:{tool_name}" in caller.scopes:
        return True
    is_read_only = bool((annotations or {}).get("readOnlyHint", False))
    if is_read_only and "mcp:read" in caller.scopes:
        return True
    if not is_read_only and "mcp:write" in caller.scopes:
        return True
    return False


class OAuthTokenExchanger:
    """
    RFC 8693 OAuth 2.0 Token Exchange helper for upstream MCP server calls.

    Prevents token passthrough and confused-deputy hijacking by minting an
    audience-attenuated, per-(principal, client_id, upstream_server) delegation token.
    """

    def __init__(self, gateway_resource: str, exchange_secret: str | None = None, ttl_seconds: int = 180) -> None:
        self.gateway_resource = gateway_resource
        self._secret = exchange_secret or secrets.token_hex(32)
        self.ttl_seconds = ttl_seconds
        self._cache: dict[tuple[str, str, str, tuple[str, ...]], tuple[str, float]] = {}
        self._consent_bindings: dict[tuple[str, str], str] = {}
        self._lock = threading.RLock()

    def bind_client_consent(self, client_id: str, server_id: str, principal: str) -> str:
        """Bind downstream client consent state to an explicit principal to prevent confused-deputy hijacking."""
        binding_digest = hashlib.sha256(f"{client_id}:{server_id}:{principal}".encode("utf-8")).hexdigest()[:24]
        with self._lock:
            self._consent_bindings[(client_id, server_id)] = principal
        return binding_digest

    def verify_consent_binding(self, client_id: str, server_id: str, principal: str) -> bool:
        with self._lock:
            bound = self._consent_bindings.get((client_id, server_id))
            return bound is None or bound == principal

    def exchange_for_upstream(
        self,
        caller: VerifiedPrincipal,
        server_id: str,
        upstream_audience: str,
        requested_scopes: list[str] | None = None,
    ) -> str:
        """Issue an RFC 8693 audience-attenuated JWT for a specific upstream MCP server."""
        if not self.verify_consent_binding(caller.client_id, server_id, caller.principal):
            raise AuthChallengeError(
                403,
                "access_denied",
                f"Confused-deputy guard: client '{caller.client_id}' consent on '{server_id}' belongs to another principal.",
            )

        effective_scopes = requested_scopes or caller.scopes or ["mcp:read"]
        if caller.scopes:
            attenuated = tuple(sorted(s for s in effective_scopes if s in caller.scopes or "mcp:admin" in caller.scopes))
        else:
            attenuated = tuple(sorted(effective_scopes))

        cache_key = (caller.principal, caller.client_id, upstream_audience, attenuated)
        now = time.time()
        with self._lock:
            cached = self._cache.get(cache_key)
            if cached and cached[1] - 10 > now:
                return cached[0]

            exp = int(now) + self.ttl_seconds
            claims: dict[str, Any] = {
                "iss": self.gateway_resource,
                "sub": caller.principal,
                "aud": upstream_audience,
                "azp": caller.client_id,
                "act": {"sub": self.gateway_resource},
                "scope": " ".join(attenuated),
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "iat": int(now),
                "exp": exp,
            }
            exchanged = mint_hs256_jwt(claims, self._secret)
            self._cache[cache_key] = (exchanged, float(exp))
            return exchanged
