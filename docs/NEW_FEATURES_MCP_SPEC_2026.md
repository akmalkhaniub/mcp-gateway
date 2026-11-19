# Proposed New Features & 2026 MCP Spec Roadmap (`mcp-gateway`)

**Scope:** Alignment upgrades for Pluralsight *Model Context Protocol: Security and Safety* and *Model Context Protocol: Advanced Features* (and the stateless `2026-07-28` MCP specification).  
**Baseline Reviewed:** `version 0.3.0` ([`src/gateway/server.py`](../src/gateway/server.py), [`src/gateway/policy.py`](../src/gateway/policy.py), [`src/gateway/registry.py`](../src/gateway/registry.py), [`src/gateway/proxy.py`](../src/gateway/proxy.py), [`src/gateway/models.py`](../src/gateway/models.py))

---

## Current Baseline Gaps

- [`src/gateway/server.py`](../src/gateway/server.py#L430-L432) advertises `"protocolVersion": "2024-11-05"` and `capabilities: {"tools": {"listChanged": True}}` without actually emitting `tools/list_changed` notifications or validating caller tokens.
- [`src/gateway/server.py`](../src/gateway/server.py#L150) reads `X-Agent-Principal` directly from an unauthenticated HTTP header rather than cryptographically verified OAuth JWT claims.
- [`src/gateway/server.py`](../src/gateway/server.py#L86-L92) configures permissive `CORSMiddleware` with `allow_origins=["*"]` and `allow_credentials=True`.
- [`src/gateway/server.py`](../src/gateway/server.py#L452-L468) returns every registered tool in `tools/list` regardless of caller identity, role, or policy restrictions.

---

## Priority 1 — MCP Security & Authorization Upgrades

### 1. OAuth 2.1 Resource Server + RFC 9728 Metadata Discovery
- **Course Mapping:** *Security & Safety* (LO 2, LO 3, LO 5)
- **Target Files:** `src/gateway/auth.py` (new), [`src/gateway/server.py`](../src/gateway/server.py)
- **Features to Add:**
  - Serve `GET /.well-known/oauth-protected-resource` (RFC 9728) declaring the gateway's canonical resource identifier (`resource`), supported scopes, and `authorization_servers` (Auth0, Keycloak, or Microsoft Entra ID).
  - Reject unauthenticated `/mcp/*` calls with `401 Unauthorized` and `WWW-Authenticate: Bearer resource_metadata="https://<host>/.well-known/oauth-protected-resource", scope="..."`.
  - Validate incoming Bearer JWTs via remote JWKS caching: verify cryptographic signature, `iss`, `aud` matching RFC 8707 Resource Indicators, and `exp` / `nbf` claims.
  - Extract `sub`, `client_id`, `scope`, and `roles` from the verified token rather than trusting plaintext `X-Agent-Principal` headers (keep header override gated behind a local dev flag only).

### 2. RFC 8693 Token Exchange & Proxy Confused-Deputy Protection
- **Course Mapping:** *Security & Safety* (LO 4, LO 5)
- **Target Files:** `src/gateway/oauth_exchange.py` (new), [`src/gateway/proxy.py`](../src/gateway/proxy.py)
- **Features to Add:**
  - Replace direct upstream header forwarding in [`src/gateway/proxy.py`](../src/gateway/proxy.py#L101-L105) with an **RFC 8693 OAuth Token Exchange** client helper that exchanges the inbound client token for a down-scoped, upstream-specific token (`audience = <upstream_server_url>`).
  - Add explicit token-passthrough guardrails rejecting tokens whose `aud` does not match this gateway.
  - Document and implement per-client state/consent binding when acting as an OAuth gateway/proxy with a single upstream client registration, preventing confused-deputy session/consent hijacking across downstream users.

### 3. Production CORS & Browser Inspector Support
- **Course Mapping:** *Security & Safety* (LO 3)
- **Target Files:** [`src/gateway/server.py`](../src/gateway/server.py#L86-L92)
- **Features to Add:**
  - Replace `allow_origins=["*"]` + `allow_credentials=True` with an environment-driven allowlist (`MCP_CORS_ALLOWED_ORIGINS`) defaulting to localhost MCP Inspector origins in dev.
  - Expose `WWW-Authenticate`, `Mcp-Session-Id`, `X-Trace-Id`, and `Retry-After` in `expose_headers` so browser-based MCP clients and Inspector OAuth flows can read discovery challenges.

### 4. Tool Poisoning & Rug-Pull Detection (Metadata Pinning)
- **Course Mapping:** *Security & Safety* (LO 1, LO 6)
- **Target Files:** [`src/gateway/registry.py`](../src/gateway/registry.py), [`src/gateway/models.py`](../src/gateway/models.py), [`src/gateway/health.py`](../src/gateway/health.py)
- **Features to Add:**
  - Compute and store a SHA-256 `definition_digest` over each discovered tool's `name`, `description`, `inputSchema`, and `annotations` upon server registration.
  - During `probe_all()` or `tools/list` refresh, flag or automatically quarantine (`enabled=False`) any upstream tool whose digest changes unexpectedly (detecting post-approval **rug pulls** and hidden prompt-injection edits in tool descriptions).
  - Scan tool descriptions for hidden control directives before exposing them in `/mcp/aggregate`.

---

## Priority 2 — MCP Protocol Modernization & Advanced Features

### 5. Least-Privilege `tools/list` Filtering & `tools/list_changed` Notifications
- **Course Mapping:** *Security & Safety* (LO 4), *Advanced Features* (LO 3)
- **Target Files:** [`src/gateway/server.py`](../src/gateway/server.py#L452-L468), [`src/gateway/policy.py`](../src/gateway/policy.py)
- **Features to Add:**
  - Filter `tools/list` dynamically using [`McpGovernanceEngine`](../src/gateway/policy.py#L83) (`effect=DENY` or missing JWT scope removes the tool from `tools/list`, not just blocking `tools/call`).
  - Support session/principal-scoped tool enable/disable toggles and emit real `notifications/tools/list_changed` JSON-RPC notifications when [`register_server`](../src/gateway/registry.py#L68), [`remove_server`](../src/gateway/registry.py#L81), policy updates, or quarantine rules alter the visible catalog.

### 6. Dual Transport Mode: Stateless `2026-07-28` Core vs. Legacy Session Mode
- **Course Mapping:** *Advanced Features* (LO 1)
- **Target Files:** [`src/gateway/server.py`](../src/gateway/server.py#L406-L512)
- **Features to Add:**
  - Add a configurable `MCP_PROTOCOL_MODE=stateless_2026|legacy_2024` setting:
    - **Stateless (`2026-07-28`) mode:** Requires per-request `_meta` capability/protocol negotiation without connection-level `initialize` pinning or stateful `Mcp-Session-Id` routing—suitable for multi-replica serverless/load-balanced scaling.
    - **Legacy (`2024-11-05`) mode:** Preserves `initialize`, `notifications/initialized`, and `Mcp-Session-Id` tracking for older clients.
  - Add an HMAC-signed opaque state/routing token option proving why raw unauthenticated handles cannot replace authorization.

### 7. Tasks Forwarding, Progress Propagation & Rich Content Passthrough
- **Course Mapping:** *Advanced Features* (LO 2, LO 3, LO 4)
- **Target Files:** [`src/gateway/server.py`](../src/gateway/server.py), [`src/gateway/proxy.py`](../src/gateway/proxy.py), [`src/gateway/telemetry.py`](../src/gateway/telemetry.py)
- **Features to Add:**
  - Route `tasks/get`, `tasks/update`, and `tasks/cancel` calls transparently to the upstream server encoded in the task handle prefix (`{server_id}:{task_id}`).
  - Propagate `input_required` elicitation payloads (`form` and `url` modes) and `notifications/progress` events cleanly without stripping `_meta` or `structuredContent` / `resource_link` / media blocks.
  - Preserve upstream `annotations` (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`) in [`McpToolInfo`](../src/gateway/models.py#L40) and add an `untrusted_server` warning flag in `/api/tools`.

---

## Verification Plan

- Add unit and integration tests in [`tests/`](../tests):
  - `tests/test_oauth_resource_server.py`: `401` RFC 9728 `WWW-Authenticate` challenge, JWKS validation (`iss`, `aud`, `exp`), scope-filtered `tools/list`, strict CORS preflight checks.
  - `tests/test_rug_pull_guard.py`: metadata digest pinning, unexpected tool description drift quarantine, and unsigned handle tampering rejection.
  - `tests/test_stateless_and_tasks.py`: stateless `_meta` routing vs. legacy `Mcp-Session-Id` behavior, `tasks/*` handle routing, and `list_changed` emission.
