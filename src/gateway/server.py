"""FastAPI application for MCP Gateway & Reverse Proxy."""

from __future__ import annotations

import os
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
from .proxy import McpProxyRouter
from .registry import McpServerRegistry

STATIC_DIR = Path(__file__).parent / "static"


def create_app(
    registry: McpServerRegistry | None = None,
    cache: McpResponseCache | None = None,
    auto_probe: bool = False,
) -> FastAPI:
    if registry is None:
        registry = McpServerRegistry()

    if cache is None:
        cache = McpResponseCache(default_ttl_seconds=60.0)

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
    app.state.prober = prober

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

        if method == "initialize":
            return JSONResponse(
                content={
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "serverInfo": {"name": "mcp-gateway-aggregator", "version": "0.2.0"},
                        "capabilities": {"tools": {"listChanged": True}},
                    },
                }
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

            # Check semantic response cache
            match = registry.find_tool(t_name)
            server_id = match[0].id if match else "unknown"
            cached = cache.get(server_id, t_name, arguments)
            if cached:
                cached["id"] = req_id
                if "result" in cached and isinstance(cached["result"], dict):
                    cached["result"]["_cached"] = True
                return JSONResponse(content=cached)

            # Route to upstream server
            result = await router.route_aggregated_tool(t_name, arguments, req_id=req_id)
            if "result" in result and not result.get("result", {}).get("isError", False):
                cache.set(server_id, t_name, arguments, result)
            return JSONResponse(content=result)

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
            cached = cache.get(server_id, t_name, arguments)
            if cached:
                cached["id"] = payload.get("id")
                if "result" in cached and isinstance(cached["result"], dict):
                    cached["result"]["_cached"] = True
                return JSONResponse(content=cached)

            resp = await router.forward_to_server(server_id, payload)
            if "result" in resp and not resp.get("result", {}).get("isError", False):
                cache.set(server_id, t_name, arguments, resp)
            return JSONResponse(content=resp)

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
