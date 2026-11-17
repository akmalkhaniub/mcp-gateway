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

from .cache import McpResponseCache
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

STATIC_DIR = Path(__file__).parent / "static"


def create_app(
    registry: McpServerRegistry | None = None,
    cache: McpResponseCache | None = None,
    governance: McpGovernanceEngine | None = None,
    auto_probe: bool = False,
) -> FastAPI:
    if registry is None:
        registry = McpServerRegistry()

    if cache is None:
        cache = McpResponseCache(default_ttl_seconds=60.0)

    if governance is None:
        governance = McpGovernanceEngine()

    router = McpProxyRouter(registry=registry)
    prober = McpHealthProber(registry=registry)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if auto_probe:
            prober.start(interval_seconds=30.0)
        yield
        prober.stop()

    app = FastAPI(
        title="MCP Gateway",
        description="High-performance reverse proxy, tool aggregator, semantic cache, and health monitor for Model Context Protocol servers.",
        version="0.2.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Store state
    app.state.registry = registry
    app.state.router = router
    app.state.cache = cache
    app.state.governance = governance
    app.state.prober = prober

    async def _execute_governed_tool_call(
        request: Request,
        server_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        req_id: Any,
        forward_fn: Any,
    ) -> JSONResponse:
        """Enforce Principal Access Boundary & HITL policy before cache/upstream execution."""
        principal = request.headers.get("X-Agent-Principal", "anonymous").strip() or "anonymous"
        approval_token = request.headers.get("X-Approval-Token")
        start_t = time.monotonic()

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
                    reason=decision.reason,
                )
            )
            return JSONResponse(
                status_code=403,
                content={
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32003,
                        "message": decision.reason,
                        "data": decision.model_dump(),
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
                reason=decision.reason,
            )
        )
        headers: dict[str, str] = {}
        if decision.dry_run_would_deny:
            headers["X-MCP-Policy-Audit"] = "DRY_RUN_WOULD_DENY"
        return JSONResponse(content=result, headers=headers)

    @app.get("/health")
    async def health() -> dict[str, Any]:
        servers = registry.list_servers()
        healthy_count = sum(1 for s in servers if s.get("health") == ServerHealth.HEALTHY.value)
        return {
            "status": "ok",
            "service": "mcp-gateway",
            "version": "0.2.0",
            "servers_count": len(servers),
            "servers_healthy": healthy_count,
            "total_tools": len(registry.list_all_tools()),
            "cache": cache.stats(),
            "governance": {
                "policies_count": len(governance.list_policies()),
                "audit_events_count": governance.audit_count(),
            },
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
    async def list_tools() -> list[dict[str, Any]]:
        tools = registry.list_all_tools()
        return [t.model_dump() for t in tools]

    @app.get("/api/cache/stats")
    async def get_cache_stats() -> dict[str, Any]:
        return cache.stats()

    @app.post("/api/cache/clear")
    async def clear_cache() -> dict[str, Any]:
        evicted = cache.clear()
        return {"status": "cleared", "evicted_entries": evicted}

    @app.get("/api/policies")
    async def list_policies() -> list[dict[str, Any]]:
        return [p.model_dump() for p in governance.list_policies()]

    @app.post("/api/policies")
    async def upsert_policy(policy: ToolAccessPolicy) -> dict[str, Any]:
        saved = governance.upsert_policy(policy)
        return {"status": "saved", "policy": saved.model_dump()}

    @app.delete("/api/policies/{policy_id}")
    async def delete_policy(policy_id: str) -> dict[str, Any]:
        removed = governance.remove_policy(policy_id)
        if not removed:
            raise HTTPException(status_code=404, detail=f"Policy '{policy_id}' not found.")
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
    ) -> list[dict[str, Any]]:
        return governance.list_audit_logs(limit=limit, principal=principal, decision=decision)

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
        session_id = request.headers.get("Mcp-Session-Id") or f"mcp-{secrets.token_hex(8)}"

        if method == "initialize":
            return JSONResponse(
                headers={"Mcp-Session-Id": session_id},
                content={
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "serverInfo": {"name": "mcp-gateway-aggregator", "version": "0.2.0"},
                        "capabilities": {"tools": {"listChanged": True}},
                    },
                },
            )

        if method == "notifications/initialized":
            return JSONResponse(
                status_code=202,
                headers={"Mcp-Session-Id": session_id},
                content={"status": "accepted"},
            )

        if method == "ping":
            return JSONResponse(content={"jsonrpc": "2.0", "id": req_id, "result": {}})

        if method == "tools/list":
            all_tools = registry.list_all_tools()
            formatted = [
                {
                    "name": t.name,
                    "description": f"[{t.server_name}] {t.description}".strip(),
                    "inputSchema": t.input_schema,
                }
                for t in all_tools
            ]
            return JSONResponse(content={"jsonrpc": "2.0", "id": req_id, "result": {"tools": formatted}})

        if method == "tools/call":
            params = payload.get("params", {})
            t_name = params.get("name")
            arguments = params.get("arguments", {})
            if not t_name:
                return JSONResponse(
                    status_code=400,
                    content={
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {"code": -32602, "message": "Missing 'name' in tools/call params."},
                    },
                )

            match = registry.find_tool(t_name)
            server_id = match[0].id if match else "unknown"
            return await _execute_governed_tool_call(
                request=request,
                server_id=server_id,
                tool_name=t_name,
                arguments=arguments,
                req_id=req_id,
                forward_fn=lambda: router.route_aggregated_tool(t_name, arguments, req_id=req_id),
            )

        return JSONResponse(
            status_code=404,
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
        if method == "tools/call":
            params = payload.get("params", {})
            t_name = params.get("name", "")
            arguments = params.get("arguments", {})
            return await _execute_governed_tool_call(
                request=request,
                server_id=server_id,
                tool_name=t_name,
                arguments=arguments,
                req_id=payload.get("id"),
                forward_fn=lambda: router.forward_to_server(server_id, payload),
            )

        resp = await router.forward_to_server(server_id, payload)
        return JSONResponse(content=resp)

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
