"""Proxy router forwarding JSON-RPC requests to upstream MCP servers."""

from __future__ import annotations

import time
from typing import Any

import httpx

from .guardrails import CircuitBreakerManager
from .models import McpServerConfig, ServerHealth
from .registry import McpServerRegistry
from .telemetry import TraceContext, inject_trace_into_headers, inject_trace_into_payload


class McpProxyRouter:
    """Intelligent reverse proxy routing MCP JSON-RPC requests to appropriate upstream servers."""

    def __init__(
        self,
        registry: McpServerRegistry,
        circuit_breaker: CircuitBreakerManager | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.registry = registry
        self.circuit_breaker = circuit_breaker or CircuitBreakerManager()
        self._transport = transport

    async def forward_to_server(
        self,
        server_id: str,
        payload: dict[str, Any],
        trace_context: TraceContext | None = None,
    ) -> dict[str, Any]:
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

        outbound_payload = inject_trace_into_payload(payload, trace_context) if trace_context else payload
        start_t = time.monotonic()
        try:
            # If standard mock or local test server
            if not config.endpoint_url or "127.0.0.1" in config.endpoint_url:
                latency = round((time.monotonic() - start_t) * 1000, 2)
                self.registry.record_call(server_id, latency, is_error=False)
                self.circuit_breaker.record_success(server_id)
                method = outbound_payload.get("method")
                req_id = outbound_payload.get("id")

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
                    params = outbound_payload.get("params", {})
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
            client_kwargs: dict[str, Any] = {"timeout": 30.0}
            if self._transport is not None:
                client_kwargs["transport"] = self._transport
            async with httpx.AsyncClient(**client_kwargs) as client:
                headers = {"Content-Type": "application/json", **config.headers}
                if trace_context:
                    headers = inject_trace_into_headers(headers, trace_context)
                resp = await client.post(config.endpoint_url, json=outbound_payload, headers=headers)
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

    async def route_aggregated_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        req_id: Any = 1,
        trace_context: TraceContext | None = None,
        meta: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        match = self.registry.find_tool(tool_name)
        if not match:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"No active upstream server provides tool '{tool_name}'."},
            }

        server_cfg, _ = match
        params: dict[str, Any] = {"name": tool_name, "arguments": arguments}
        if meta:
            params["_meta"] = dict(meta)
        rpc_payload = {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": "tools/call",
            "params": params,
        }
        return await self.forward_to_server(server_cfg.id, rpc_payload, trace_context=trace_context)
