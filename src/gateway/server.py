"""FastAPI application for MCP Gateway & Reverse Proxy."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .models import McpServerConfig, ServerHealth
from .proxy import McpProxyRouter
from .registry import McpServerRegistry

STATIC_DIR = Path(__file__).parent / "static"


def create_app(registry: McpServerRegistry | None = None) -> FastAPI:
    if registry is None:
        registry = McpServerRegistry()

    router = McpProxyRouter(registry=registry)

    app = FastAPI(
        title="MCP Gateway",
        description="High-performance reverse proxy, tool aggregator, and health monitor for Model Context Protocol servers.",
        version="0.1.0",
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

    @app.get("/health")
    async def health() -> dict[str, Any]:
        servers = registry.list_servers()
        healthy_count = sum(1 for s in servers if s.get("health") == ServerHealth.HEALTHY.value)
        return {
            "status": "ok",
            "service": "mcp-gateway",
            "version": "0.1.0",
            "servers_count": len(servers),
            "servers_healthy": healthy_count,
            "total_tools": len(registry.list_all_tools()),
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

    @app.get("/api/tools")
    async def list_tools() -> list[dict[str, Any]]:
        tools = registry.list_all_tools()
        return [t.model_dump() for t in tools]

    @app.post("/mcp/aggregate")
    async def aggregate_mcp(request: Request) -> JSONResponse:
        """Universal MCP endpoint aggregating all upstream tools."""
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
                        "serverInfo": {"name": "mcp-gateway-aggregator", "version": "0.1.0"},
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
            result = await router.route_aggregated_tool(t_name, arguments, req_id=req_id)
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
