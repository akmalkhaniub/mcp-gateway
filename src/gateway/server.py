"""FastAPI application for MCP Gateway & Reverse Proxy."""

from __future__ import annotations

import os
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .auth import (
    AuthChallengeError,
    GatewayOAuthSettings,
    OAuthTokenExchanger,
    VerifiedPrincipal,
    authenticate_mcp_request,
    build_protected_resource_metadata,
    build_www_authenticate_header,
    is_scope_sufficient,
)
from .cache import McpResponseCache
from .guardrails import CircuitBreakerManager, TokenBucketRateLimiter
from .health import McpHealthProber
from .models import McpServerConfig, ServerHealth
from .policy import (
    ApprovalTokenRequest,
    AuditLogEntry,
    McpGovernanceEngine,
    ToolAccessPolicy,
)
from .proxy import McpProxyRouter
from .registry import McpServerRegistry
from .stateless import (
    ProtocolMode,
    StatelessHandleError,
    StatelessHandleManager,
    negotiate_protocol_mode,
    parse_task_handle,
)
from .telemetry import (
    GatewaySpan,
    GatewayTelemetryCollector,
    TraceContext,
    attach_trace_meta_to_response,
    extract_trace_context,
)

STATIC_DIR = Path(__file__).parent / "static"


def create_app(
    registry: McpServerRegistry | None = None,
    cache: McpResponseCache | None = None,
    governance: McpGovernanceEngine | None = None,
    rate_limiter: TokenBucketRateLimiter | None = None,
    circuit_breaker: CircuitBreakerManager | None = None,
    telemetry: GatewayTelemetryCollector | None = None,
    router: McpProxyRouter | None = None,
    auto_probe: bool = False,
    oauth_settings: GatewayOAuthSettings | None = None,
    token_exchanger: OAuthTokenExchanger | None = None,
    handle_manager: StatelessHandleManager | None = None,
    default_protocol_mode: ProtocolMode | None = None,
) -> FastAPI:
    if registry is None:
        registry = McpServerRegistry()

    if cache is None:
        cache = McpResponseCache(default_ttl_seconds=60.0)

    if governance is None:
        governance = McpGovernanceEngine()

    if rate_limiter is None:
        rate_limiter = TokenBucketRateLimiter(capacity=60.0, refill_rate_per_sec=2.0)

    if circuit_breaker is None:
        circuit_breaker = CircuitBreakerManager(failure_threshold=3, recovery_timeout_seconds=30.0)

    if telemetry is None:
        telemetry = GatewayTelemetryCollector()

    if router is None:
        router = McpProxyRouter(registry=registry, circuit_breaker=circuit_breaker)
    prober = McpHealthProber(registry=registry)
    oauth_cfg = oauth_settings or GatewayOAuthSettings()
    exchanger = token_exchanger or OAuthTokenExchanger(gateway_resource=oauth_cfg.resource)
    handles = handle_manager or StatelessHandleManager()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if auto_probe:
            prober.start(interval_seconds=30.0)
        yield
        prober.stop()

    app = FastAPI(
        title="MCP Gateway",
        description="High-performance reverse proxy, tool aggregator, semantic cache, rate limiter, circuit breaker, and health monitor for Model Context Protocol servers.",
        version="0.3.0",
        lifespan=lifespan,
    )

    allowed_origins = [
        origin.strip()
        for origin in os.getenv(
            "MCP_CORS_ALLOWED_ORIGINS",
            "http://127.0.0.1:8000,http://localhost:8000,http://localhost:6274",
        ).split(",")
        if origin.strip()
    ]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "Mcp-Session-Id",
            "MCP-Protocol-Version",
            "X-Agent-Principal",
            "X-Approval-Token",
            "traceparent",
            "tracestate",
            "baggage",
        ],
        expose_headers=["WWW-Authenticate", "Mcp-Session-Id", "X-Trace-Id", "Retry-After"],
    )

    # Store state
    app.state.registry = registry
    app.state.router = router
    app.state.cache = cache
    app.state.governance = governance
    app.state.rate_limiter = rate_limiter
    app.state.circuit_breaker = circuit_breaker
    app.state.telemetry = telemetry
    app.state.prober = prober
    app.state.oauth_settings = oauth_cfg
    app.state.token_exchanger = exchanger
    app.state.handle_manager = handles

    def _trace_headers(ctx: TraceContext, extra: dict[str, str] | None = None) -> dict[str, str]:
        headers = {"traceparent": ctx.traceparent, "X-Trace-Id": ctx.trace_id}
        if ctx.tracestate:
            headers["tracestate"] = ctx.tracestate
        if extra:
            headers.update(extra)
        return headers

    def _record_span(
        ctx: TraceContext,
        operation: str,
        server_id: str,
        principal: str,
        status: str,
        latency_ms: float,
        tool_name: str | None = None,
        cached: bool = False,
    ) -> None:
        telemetry.record_span(
            GatewaySpan(
                trace_id=ctx.trace_id,
                span_id=ctx.span_id,
                parent_span_id=ctx.parent_span_id,
                operation=operation,
                server_id=server_id,
                tool_name=tool_name,
                principal=principal,
                status=status,
                cached=cached,
                latency_ms=latency_ms,
                source=ctx.source,
                tracestate=ctx.tracestate,
                baggage=ctx.baggage,
            )
        )

    def _authenticate_or_401(
        request: Request,
        trace_ctx: TraceContext,
    ) -> VerifiedPrincipal | JSONResponse:
        try:
            return authenticate_mcp_request(request, oauth_cfg)
        except AuthChallengeError as exc:
            www_auth = build_www_authenticate_header(
                request,
                oauth_cfg,
                error=exc.error,
                description=exc.description,
                scope=exc.required_scope,
            )
            return JSONResponse(
                status_code=exc.status_code,
                headers=_trace_headers(trace_ctx, {"WWW-Authenticate": www_auth}),
                content={
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {
                        "code": -32001 if exc.status_code == 401 else -32003,
                        "message": exc.description,
                        "data": {"error": exc.error, "trace_id": trace_ctx.trace_id},
                    },
                },
            )

    def _exchange_upstream_token(caller: VerifiedPrincipal, server_id: str) -> str | None:
        if caller.auth_method != "oauth2_bearer_jwt":
            return None
        cfg = registry.get_server(server_id)
        if not cfg or not cfg.endpoint_url:
            return None
        return exchanger.exchange_for_upstream(
            caller=caller,
            server_id=server_id,
            upstream_audience=cfg.endpoint_url,
        )

    def _verify_stateless_handle(
        payload: dict[str, Any],
        caller: VerifiedPrincipal,
        trace_ctx: TraceContext,
    ) -> JSONResponse | None:
        params = payload.get("params")
        if not isinstance(params, dict):
            return None
        meta = params.get("_meta")
        if not isinstance(meta, dict) or "state_handle" not in meta:
            return None
        raw_handle = meta.get("state_handle")
        try:
            handles.verify_handle(str(raw_handle), expected_principal=caller.principal)
        except StatelessHandleError as exc:
            return JSONResponse(
                status_code=403,
                headers=_trace_headers(trace_ctx),
                content={
                    "jsonrpc": "2.0",
                    "id": payload.get("id"),
                    "error": {
                        "code": -32003,
                        "message": str(exc),
                        "data": {"trace_id": trace_ctx.trace_id},
                    },
                },
            )
        return None

    async def _execute_governed_tool_call(
        request: Request,
        server_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        req_id: Any,
        trace_ctx: TraceContext,
        forward_fn: Any,
        caller: VerifiedPrincipal | None = None,
        tool_annotations: dict[str, Any] | None = None,
    ) -> JSONResponse:
        """Enforce OAuth scope, Rate Limiter, Principal Access Boundary & HITL policy before execution."""
        if caller is None:
            auth_res = _authenticate_or_401(request, trace_ctx)
            if isinstance(auth_res, JSONResponse):
                return auth_res
            caller = auth_res
        principal = caller.principal
        approval_token = request.headers.get("X-Approval-Token")
        start_t = time.monotonic()

        if not is_scope_sufficient(caller, tool_annotations, tool_name):
            latency_ms = round((time.monotonic() - start_t) * 1000, 2)
            _record_span(trace_ctx, "mcp.tools/call", server_id, principal, "insufficient_scope", latency_ms, tool_name)
            required = "mcp:read" if (tool_annotations or {}).get("readOnlyHint") else "mcp:write"
            www_auth = build_www_authenticate_header(
                request,
                oauth_cfg,
                error="insufficient_scope",
                description=f"Caller scopes {caller.scopes} insufficient for tool '{tool_name}'.",
                scope=required,
            )
            return JSONResponse(
                status_code=403,
                headers=_trace_headers(trace_ctx, {"WWW-Authenticate": www_auth}),
                content={
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32003,
                        "message": f"Insufficient OAuth scope for tool '{tool_name}'. Required: {required}.",
                        "data": {"required_scope": required, "trace_id": trace_ctx.trace_id},
                    },
                },
            )

        # 1. Token-bucket rate limit check
        allowed_rate, retry_after = rate_limiter.consume(principal)
        if not allowed_rate:
            latency_ms = round((time.monotonic() - start_t) * 1000, 2)
            governance.record_audit(
                AuditLogEntry(
                    principal=principal,
                    server_id=server_id,
                    tool_name=tool_name,
                    decision="rate_limited",
                    policy_id="rate_limiter",
                    mode="enforce",
                    cached=False,
                    latency_ms=latency_ms,
                    trace_id=trace_ctx.trace_id,
                    span_id=trace_ctx.span_id,
                    reason=f"Rate limit exceeded for principal '{principal}'. Retry after {retry_after}s.",
                )
            )
            _record_span(trace_ctx, "mcp.tools/call", server_id, principal, "rate_limited", latency_ms, tool_name)
            return JSONResponse(
                status_code=429,
                headers=_trace_headers(trace_ctx, {"Retry-After": str(retry_after)}),
                content={
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32004,
                        "message": f"Rate limit exceeded for principal '{principal}'. Retry after {retry_after}s.",
                        "data": {"retry_after_seconds": retry_after, "trace_id": trace_ctx.trace_id},
                    },
                },
            )

        decision = governance.evaluate(
            principal=principal,
            server_id=server_id,
            tool_name=tool_name,
            approval_token=approval_token,
        )
        if not decision.allowed:
            latency_ms = round((time.monotonic() - start_t) * 1000, 2)
            governance.record_audit(
                AuditLogEntry(
                    principal=principal,
                    server_id=server_id,
                    tool_name=tool_name,
                    decision="denied",
                    policy_id=decision.matched_policy_id,
                    mode=decision.mode.value,
                    cached=False,
                    latency_ms=latency_ms,
                    trace_id=trace_ctx.trace_id,
                    span_id=trace_ctx.span_id,
                    reason=decision.reason,
                )
            )
            _record_span(trace_ctx, "mcp.tools/call", server_id, principal, "denied", latency_ms, tool_name)
            err_data = decision.model_dump()
            err_data["trace_id"] = trace_ctx.trace_id
            return JSONResponse(
                status_code=403,
                headers=_trace_headers(trace_ctx),
                content={
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32003,
                        "message": decision.reason,
                        "data": err_data,
                    },
                },
            )

        cached = cache.get(server_id, tool_name, arguments)
        if cached:
            cached["id"] = req_id
            if "result" in cached and isinstance(cached["result"], dict):
                cached["result"]["_cached"] = True
            result = cached
            was_cached = True
        else:
            result = await forward_fn()
            if "result" in result and not result.get("result", {}).get("isError", False):
                cache.set(server_id, tool_name, arguments, result)
            was_cached = False

        latency_ms = round((time.monotonic() - start_t) * 1000, 2)
        has_error = "error" in result or bool(result.get("result", {}).get("isError", False))
        audit_decision = "dry_run_would_deny" if decision.dry_run_would_deny else "allowed"
        governance.record_audit(
            AuditLogEntry(
                principal=principal,
                server_id=server_id,
                tool_name=tool_name,
                decision=audit_decision,
                policy_id=decision.matched_policy_id,
                mode=decision.mode.value,
                cached=was_cached,
                latency_ms=latency_ms,
                trace_id=trace_ctx.trace_id,
                span_id=trace_ctx.span_id,
                reason=decision.reason,
            )
        )
        _record_span(
            trace_ctx,
            "mcp.tools/call",
            server_id,
            principal,
            "error" if has_error else "ok",
            latency_ms,
            tool_name=tool_name,
            cached=was_cached,
        )
        enriched = attach_trace_meta_to_response(
            result,
            trace_ctx,
            extra={"cached": was_cached, "latency_ms": latency_ms},
        )
        extra_hdrs = {"X-MCP-Policy-Audit": "DRY_RUN_WOULD_DENY"} if decision.dry_run_would_deny else None
        return JSONResponse(content=enriched, headers=_trace_headers(trace_ctx, extra_hdrs))

    @app.get("/health")
    async def health() -> dict[str, Any]:
        servers = registry.list_servers()
        healthy_count = sum(1 for s in servers if s.get("health") == ServerHealth.HEALTHY.value)
        return {
            "status": "ok",
            "service": "mcp-gateway",
            "version": "0.3.0",
            "oauth_mode": oauth_cfg.auth_mode,
            "protocol_mode": (default_protocol_mode or ProtocolMode.LEGACY_2024).value,
            "servers_count": len(servers),
            "servers_healthy": healthy_count,
            "total_tools": len(registry.list_all_tools()),
            "cache": cache.stats(),
            "governance": {
                "policies_count": len(governance.list_policies()),
                "audit_events_count": governance.audit_count(),
            },
            "guardrails": {
                "rate_limiter": rate_limiter.stats(),
                "circuits": circuit_breaker.all_statuses(),
            },
            "telemetry": telemetry.stats(),
        }

    @app.get("/api/servers")
    async def list_servers() -> list[dict[str, Any]]:
        return registry.list_servers()

    @app.post("/api/servers")
    async def register_server(config: McpServerConfig) -> dict[str, Any]:
        registry.register_server(config)
        return {"status": "registered", "server": config.model_dump()}

    @app.delete("/api/servers/{server_id}")
    async def unregister_server(server_id: str) -> dict[str, Any]:
        removed = registry.remove_server(server_id)
        if not removed:
            raise HTTPException(status_code=404, detail=f"Server '{server_id}' not found.")
        return {"status": "removed", "server_id": server_id}

    @app.post("/api/servers/probe")
    async def probe_servers() -> list[dict[str, Any]]:
        return await prober.probe_all()

    @app.get("/api/tools")
    async def list_tools(include_quarantined: bool = True) -> list[dict[str, Any]]:
        tools = registry.list_all_tools(include_quarantined=include_quarantined)
        return [
            {
                **t.model_dump(),
                "untrusted_server": t.server_id != "attractor-factory",
            }
            for t in tools
        ]

    @app.get("/api/notifications")
    async def list_notifications() -> list[dict[str, Any]]:
        return registry.list_notifications()

    @app.get("/api/cache/stats")
    async def get_cache_stats() -> dict[str, Any]:
        return cache.stats()

    @app.post("/api/cache/clear")
    async def clear_cache() -> dict[str, Any]:
        evicted = cache.clear()
        return {"status": "cleared", "evicted_entries": evicted}

    @app.get("/api/guardrails/status")
    async def get_guardrails_status() -> dict[str, Any]:
        return {
            "rate_limiter": rate_limiter.stats(),
            "circuits": circuit_breaker.all_statuses(),
        }

    @app.post("/api/guardrails/circuits/{server_id}/reset")
    async def reset_circuit_breaker(server_id: str) -> dict[str, Any]:
        circuit_breaker.reset(server_id)
        return {"status": "reset", "circuit": circuit_breaker.status(server_id)}

    @app.get("/api/policies")
    async def list_policies() -> list[dict[str, Any]]:
        return [p.model_dump() for p in governance.list_policies()]

    @app.post("/api/policies")
    async def upsert_policy(policy: ToolAccessPolicy) -> dict[str, Any]:
        saved = governance.upsert_policy(policy)
        registry.emit_tools_list_changed("policy_upserted")
        return {"status": "saved", "policy": saved.model_dump()}

    @app.delete("/api/policies/{policy_id}")
    async def delete_policy(policy_id: str) -> dict[str, Any]:
        removed = governance.remove_policy(policy_id)
        if not removed:
            raise HTTPException(status_code=404, detail=f"Policy '{policy_id}' not found.")
        registry.emit_tools_list_changed("policy_deleted")
        return {"status": "removed", "policy_id": policy_id}

    @app.post("/api/policies/approval-token")
    async def issue_approval_token(req: ApprovalTokenRequest) -> dict[str, Any]:
        token, exp = governance.issue_approval_token(
            principal=req.principal,
            server_id=req.server_id,
            tool_name=req.tool_name,
            ttl_seconds=req.ttl_seconds,
        )
        return {
            "approval_token": token,
            "principal": req.principal,
            "server_id": req.server_id,
            "tool_name": req.tool_name,
            "expires_at": exp,
        }

    @app.get("/api/audit/logs")
    async def list_audit_logs(
        limit: int = 100,
        principal: str | None = None,
        decision: str | None = None,
        trace_id: str | None = None,
    ) -> list[dict[str, Any]]:
        return governance.list_audit_logs(
            limit=limit,
            principal=principal,
            decision=decision,
            trace_id=trace_id,
        )

    @app.get("/api/telemetry/spans")
    async def list_telemetry_spans(
        limit: int = 100,
        trace_id: str | None = None,
        server_id: str | None = None,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        return telemetry.list_spans(
            limit=limit,
            trace_id=trace_id,
            server_id=server_id,
            status=status,
        )

    @app.get("/.well-known/oauth-protected-resource")
    async def oauth_protected_resource_metadata(request: Request) -> dict[str, Any]:
        """RFC 9728 OAuth 2.0 Protected Resource Metadata discovery endpoint."""
        return build_protected_resource_metadata(oauth_cfg, base_url=str(request.base_url))

    @app.post("/mcp/aggregate")
    async def aggregate_mcp(request: Request) -> JSONResponse:
        """Universal MCP endpoint aggregating all upstream tools with semantic response caching."""
        try:
            payload = await request.json()
        except Exception:
            return JSONResponse(
                status_code=400,
                content={"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error (invalid JSON)"}},
            )

        method = payload.get("method")
        req_id = payload.get("id")
        trace_ctx = extract_trace_context(request.headers, payload)
        protocol_mode, protocol_version = negotiate_protocol_mode(
            request.headers,
            payload,
            default_mode=default_protocol_mode,
        )

        auth_res = _authenticate_or_401(request, trace_ctx)
        if isinstance(auth_res, JSONResponse):
            return auth_res
        caller = auth_res

        handle_err = _verify_stateless_handle(payload, caller, trace_ctx)
        if handle_err is not None:
            return handle_err

        session_id = request.headers.get("Mcp-Session-Id") or f"mcp-{secrets.token_hex(8)}"
        extra_resp_headers: dict[str, str] = {"MCP-Protocol-Version": protocol_version}
        if protocol_mode == ProtocolMode.LEGACY_2024:
            extra_resp_headers["Mcp-Session-Id"] = session_id

        def _stateless_meta_extra(server_id: str = "aggregate", cursor: str = "ok") -> dict[str, Any]:
            if protocol_mode != ProtocolMode.STATELESS_2026:
                return {}
            return {
                "protocolVersion": protocol_version,
                "stateless": True,
                "state_handle": handles.mint_handle(
                    principal=caller.principal,
                    server_id=server_id,
                    cursor=cursor,
                ),
            }

        if method == "initialize":
            return JSONResponse(
                headers=_trace_headers(trace_ctx, extra_resp_headers),
                content=attach_trace_meta_to_response(
                    {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "protocolVersion": protocol_version,
                            "serverInfo": {"name": "mcp-gateway-aggregator", "version": "0.3.0"},
                            "capabilities": {
                                "tools": {"listChanged": True},
                                "tasks": {"list": True, "cancel": True},
                                "stateless": protocol_mode == ProtocolMode.STATELESS_2026,
                            },
                        },
                    },
                    trace_ctx,
                    extra=_stateless_meta_extra("aggregate", "initialized"),
                ),
            )

        if method == "notifications/initialized":
            return JSONResponse(
                status_code=202,
                headers=_trace_headers(trace_ctx, extra_resp_headers),
                content={"status": "accepted"},
            )

        if method == "ping":
            return JSONResponse(
                headers=_trace_headers(trace_ctx, extra_resp_headers),
                content={"jsonrpc": "2.0", "id": req_id, "result": {}},
            )

        if method == "tools/list":
            principal = caller.principal
            all_tools = registry.list_all_tools()
            formatted = [
                {
                    "name": t.name,
                    "description": f"[{t.server_name}] {t.description}".strip(),
                    "inputSchema": t.input_schema,
                    **({"annotations": t.annotations} if t.annotations else {}),
                }
                for t in all_tools
                if governance.is_tool_visible(principal=principal, server_id=t.server_id, tool_name=t.name)
                and is_scope_sufficient(caller, t.annotations, t.name)
            ]
            return JSONResponse(
                headers=_trace_headers(trace_ctx, extra_resp_headers),
                content=attach_trace_meta_to_response(
                    {"jsonrpc": "2.0", "id": req_id, "result": {"tools": formatted}},
                    trace_ctx,
                    extra=_stateless_meta_extra("aggregate", f"tools:{len(formatted)}"),
                ),
            )

        if method in {"tasks/get", "tasks/update", "tasks/cancel"}:
            params = payload.get("params", {})
            raw_task_id = str(params.get("taskId") or params.get("task_id") or "").strip()
            parsed = parse_task_handle(raw_task_id)
            if not parsed:
                return JSONResponse(
                    status_code=400,
                    headers=_trace_headers(trace_ctx, extra_resp_headers),
                    content={
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {"code": -32602, "message": "Invalid taskId handle. Expected '{server_id}:{task_id}'."},
                    },
                )
            target_server_id, upstream_task_id = parsed
            try:
                upstream_token = _exchange_upstream_token(caller, target_server_id)
            except AuthChallengeError as exc:
                return JSONResponse(
                    status_code=exc.status_code,
                    headers=_trace_headers(trace_ctx, extra_resp_headers),
                    content={"jsonrpc": "2.0", "id": req_id, "error": {"code": -32003, "message": exc.description}},
                )
            forwarded_payload = {
                **payload,
                "params": {**params, "taskId": upstream_task_id},
            }
            start_t = time.monotonic()
            fwd_kwargs: dict[str, Any] = {"trace_context": trace_ctx}
            if upstream_token is not None:
                fwd_kwargs["upstream_bearer_token"] = upstream_token
            resp = await router.forward_to_server(
                target_server_id,
                forwarded_payload,
                **fwd_kwargs,
            )
            latency_ms = round((time.monotonic() - start_t) * 1000, 2)
            _record_span(
                trace_ctx,
                f"mcp.{method}",
                target_server_id,
                caller.principal,
                "error" if "error" in resp else "ok",
                latency_ms,
            )
            enriched = attach_trace_meta_to_response(
                resp,
                trace_ctx,
                extra={"latency_ms": latency_ms, **_stateless_meta_extra(target_server_id, upstream_task_id)},
            )
            return JSONResponse(headers=_trace_headers(trace_ctx, extra_resp_headers), content=enriched)

        if method == "tools/call":
            params = payload.get("params", {})
            t_name = params.get("name")
            arguments = params.get("arguments", {})
            raw_meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else None
            if not t_name:
                return JSONResponse(
                    status_code=400,
                    headers=_trace_headers(trace_ctx, extra_resp_headers),
                    content={
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {"code": -32602, "message": "Missing 'name' in tools/call params."},
                    },
                )

            match = registry.find_tool(t_name)
            server_id = match[0].id if match else "unknown"
            tool_annotations = match[1].annotations if match else None
            try:
                upstream_token = _exchange_upstream_token(caller, server_id) if match else None
            except AuthChallengeError as exc:
                return JSONResponse(
                    status_code=exc.status_code,
                    headers=_trace_headers(trace_ctx, extra_resp_headers),
                    content={"jsonrpc": "2.0", "id": req_id, "error": {"code": -32003, "message": exc.description}},
                )
            return await _execute_governed_tool_call(
                request=request,
                server_id=server_id,
                tool_name=t_name,
                arguments=arguments,
                req_id=req_id,
                trace_ctx=trace_ctx,
                caller=caller,
                tool_annotations=tool_annotations,
                forward_fn=lambda: router.route_aggregated_tool(
                    t_name,
                    arguments,
                    req_id=req_id,
                    trace_context=trace_ctx,
                    meta=raw_meta,
                    **({"upstream_bearer_token": upstream_token} if upstream_token is not None else {}),
                ),
            )

        return JSONResponse(
            status_code=404,
            headers=_trace_headers(trace_ctx, extra_resp_headers),
            content={
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Method '{method}' not implemented by MCP Gateway aggregator."},
            },
        )

    @app.post("/mcp/{server_id}")
    async def proxy_to_server(server_id: str, request: Request) -> JSONResponse:
        try:
            payload = await request.json()
        except Exception:
            return JSONResponse(
                status_code=400,
                content={"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error (invalid JSON)"}},
            )

        method = payload.get("method")
        trace_ctx = extract_trace_context(request.headers, payload)
        auth_res = _authenticate_or_401(request, trace_ctx)
        if isinstance(auth_res, JSONResponse):
            return auth_res
        caller = auth_res

        handle_err = _verify_stateless_handle(payload, caller, trace_ctx)
        if handle_err is not None:
            return handle_err

        try:
            upstream_token = _exchange_upstream_token(caller, server_id)
        except AuthChallengeError as exc:
            return JSONResponse(
                status_code=exc.status_code,
                headers=_trace_headers(trace_ctx),
                content={"jsonrpc": "2.0", "id": payload.get("id"), "error": {"code": -32003, "message": exc.description}},
            )

        if method == "tools/call":
            params = payload.get("params", {})
            t_name = params.get("name", "")
            arguments = params.get("arguments", {})
            tool_match = next(
                (t for t in registry.list_all_tools(include_quarantined=True) if t.server_id == server_id and t.name == t_name),
                None,
            )
            return await _execute_governed_tool_call(
                request=request,
                server_id=server_id,
                tool_name=t_name,
                arguments=arguments,
                req_id=payload.get("id"),
                trace_ctx=trace_ctx,
                caller=caller,
                tool_annotations=tool_match.annotations if tool_match else None,
                forward_fn=lambda: router.forward_to_server(
                    server_id,
                    payload,
                    trace_context=trace_ctx,
                    **({"upstream_bearer_token": upstream_token} if upstream_token is not None else {}),
                ),
            )

        start_t = time.monotonic()
        resp = await router.forward_to_server(
            server_id,
            payload,
            trace_context=trace_ctx,
            **({"upstream_bearer_token": upstream_token} if upstream_token is not None else {}),
        )
        latency_ms = round((time.monotonic() - start_t) * 1000, 2)
        principal = caller.principal
        if method == "tools/list" and isinstance(resp.get("result"), dict) and isinstance(resp["result"].get("tools"), list):
            quarantined_names = {
                t.name
                for t in registry.list_all_tools(include_quarantined=True)
                if t.server_id == server_id and t.quarantined
            }
            resp["result"]["tools"] = [
                tool
                for tool in resp["result"]["tools"]
                if isinstance(tool, dict)
                and tool.get("name") not in quarantined_names
                and governance.is_tool_visible(
                    principal=principal,
                    server_id=server_id,
                    tool_name=str(tool.get("name", "")),
                )
                and is_scope_sufficient(caller, tool.get("annotations"), str(tool.get("name", "")))
            ]
        _record_span(
            trace_ctx,
            f"mcp.{method or 'proxy'}",
            server_id,
            principal,
            "error" if "error" in resp else "ok",
            latency_ms,
        )
        enriched = attach_trace_meta_to_response(resp, trace_ctx, extra={"latency_ms": latency_ms})
        return JSONResponse(content=enriched, headers=_trace_headers(trace_ctx))

    # Static / Dashboard UI
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.get("/", response_class=HTMLResponse)
    async def dashboard() -> HTMLResponse:
        html_file = STATIC_DIR / "index.html"
        if html_file.exists():
            return HTMLResponse(content=html_file.read_text(encoding="utf-8"))
        return HTMLResponse(
            content="""<!DOCTYPE html>
<html>
<head><title>MCP Gateway</title></head>
<body><h1>MCP Gateway & Reverse Proxy</h1><p>Status: Online</p><p>Explore <a href="/docs">API Docs</a> or <a href="/api/servers">Servers</a>.</p></body>
</html>"""
        )

    return app


app = create_app()
