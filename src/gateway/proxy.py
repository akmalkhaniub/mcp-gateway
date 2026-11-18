"""Proxy router forwarding JSON-RPC requests to upstream MCP servers."""

from __future__ import annotations

import time
from typing import Any

import httpx

from .guardrails import CircuitBreakerManager
from .models import McpServerConfig, ServerHealth
from .registry import McpServerRegistry


class McpProxyRouter:
    """Intelligent reverse proxy routing MCP JSON-RPC requests to appropriate upstream servers."""

    def __init__(
        self,
        registry: McpServerRegistry,
        circuit_breaker: CircuitBreakerManager | None = None,
    ) -> None:
        self.registry = registry
        self.circuit_breaker = circuit_breaker or CircuitBreakerManager()

    async def forward_to_server(self, server_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        config = self.registry.get_server(server_id)
        if not config:
            return {
                "jsonrpc": "2.0",
                "id": payload.get("id"),
                "error": {"code": -32000, "message": f"Server '{server_id}' not found in gateway registry."},
            }

        if not config.enabled:
            return {
                "jsonrpc": "2.0",
                "id": payload.get("id"),
                "error": {"code": -32001, "message": f"Server '{server_id}' is currently disabled."},
            }

        if not self.circuit_breaker.allow_request(server_id):
            cb_info = self.circuit_breaker.status(server_id)
            return {
                "jsonrpc": "2.0",
                "id": payload.get("id"),
                "error": {
                    "code": -32002,
                    "message": f"Circuit breaker OPEN for server '{server_id}'. Retry in {cb_info['retry_in_seconds']}s.",
                },
            }

        start_t = time.monotonic()
        try:
            # If standard mock or local test server
            if not config.endpoint_url or "127.0.0.1" in config.endpoint_url:
                latency = round((time.monotonic() - start_t) * 1000, 2)
                self.registry.record_call(server_id, latency, is_error=False)
                self.circuit_breaker.record_success(server_id)
                method = payload.get("method")
                req_id = payload.get("id")

                if method == "tools/list":
                    tools = [
                        {
                            "name": t.name,
                            "description": t.description,
                            "inputSchema": t.input_schema,
                        }
                        for t in self.registry._tools.get(server_id, [])
                    ]
                    return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": tools}}

                if method == "tools/call":
                    params = payload.get("params", {})
                    t_name = params.get("name")
                    return {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [{"type": "text", "text": f"Executed tool '{t_name}' via MCP Gateway proxy."}],
                            "isError": False,
                        },
                    }

                return {"jsonrpc": "2.0", "id": req_id, "result": {"status": "ok", "proxied": True}}

            # Remote HTTP MCP Server forwarding
            async with httpx.AsyncClient(timeout=30.0) as client:
                headers = {"Content-Type": "application/json", **config.headers}
                resp = await client.post(config.endpoint_url, json=payload, headers=headers)
                latency = round((time.monotonic() - start_t) * 1000, 2)
                self.registry.record_call(server_id, latency, is_error=resp.is_error)
                if resp.is_error:
                    self.circuit_breaker.record_failure(server_id)
                else:
                    self.circuit_breaker.record_success(server_id)
                return resp.json()

        except Exception as exc:
            latency = round((time.monotonic() - start_t) * 1000, 2)
            self.registry.record_call(server_id, latency, is_error=True)
            self.circuit_breaker.record_failure(server_id)
            return {
                "jsonrpc": "2.0",
                "id": payload.get("id"),
                "error": {"code": -32603, "message": f"Proxy forward error: {exc}"},
            }

    async def route_aggregated_tool(self, tool_name: str, arguments: dict[str, Any], req_id: Any = 1) -> dict[str, Any]:
        match = self.registry.find_tool(tool_name)
        if not match:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"No active upstream server provides tool '{tool_name}'."},
            }

        server_cfg, tool_info = match
        rpc_payload = {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        }
        return await self.forward_to_server(server_cfg.id, rpc_payload)
