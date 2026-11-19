"""Tests for W3C Trace Context & OTel-over-MCP (_meta) propagation and span telemetry."""

from __future__ import annotations

import json

import httpx
from fastapi.testclient import TestClient

from gateway.models import McpServerConfig, McpToolInfo, ServerTransport
from gateway.proxy import McpProxyRouter
from gateway.registry import McpServerRegistry
from gateway.server import create_app


def test_w3c_traceparent_from_http_header_propagates_and_records_span() -> None:
    client = TestClient(create_app())
    incoming_trace_id = "4bf92f3577b34da6a3ce929d0e0e4736"
    incoming_parent = "00f067aa0ba902b7"
    incoming_tp = f"00-{incoming_trace_id}-{incoming_parent}-01"

    resp = client.post(
        "/mcp/aggregate",
        json={
            "jsonrpc": "2.0",
            "id": 101,
            "method": "tools/call",
            "params": {"name": "attractor_lint_pipeline", "arguments": {"dot_source": "digraph { a -> b; }"}},
        },
        headers={
            "traceparent": incoming_tp,
            "tracestate": "congo=t61rcWkgMzE",
            "baggage": "tenant_id=acme,env=prod",
            "X-Agent-Principal": "principal://agents.global.org-1/planner",
        },
    )
    assert resp.status_code == 200
    assert resp.headers.get("X-Trace-Id") == incoming_trace_id
    out_tp = resp.headers.get("traceparent", "")
    assert out_tp.startswith(f"00-{incoming_trace_id}-")
    assert out_tp != incoming_tp  # Gateway minted a child span_id

    meta = resp.json()["result"]["_meta"]
    assert meta["trace_id"] == incoming_trace_id
    assert meta["parent_span_id"] == incoming_parent
    assert meta["traceparent"] == out_tp
    assert meta["cached"] is False

    spans = client.get(f"/api/telemetry/spans?trace_id={incoming_trace_id}").json()
    assert len(spans) == 1
    assert spans[0]["trace_id"] == incoming_trace_id
    assert spans[0]["parent_span_id"] == incoming_parent
    assert spans[0]["source"] == "http_header"
    assert spans[0]["tracestate"] == "congo=t61rcWkgMzE"
    assert spans[0]["baggage"] == "tenant_id=acme,env=prod"
    assert spans[0]["status"] == "ok"

    audits = client.get(f"/api/audit/logs?trace_id={incoming_trace_id}").json()
    assert len(audits) == 1
    assert audits[0]["trace_id"] == incoming_trace_id
    assert audits[0]["span_id"] == meta["span_id"]


def test_mcp_meta_traceparent_preferred_and_forwarded_to_remote_upstream() -> None:
    captured: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode("utf-8"))
        captured.append({"headers": dict(request.headers), "body": body})
        return httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": body.get("id"),
                "result": {"content": [{"type": "text", "text": "remote-ok"}], "isError": False},
            },
        )

    reg = McpServerRegistry()
    reg.register_server(
        McpServerConfig(
            id="remote-crm",
            name="Remote CRM MCP",
            transport=ServerTransport.HTTP,
            endpoint_url="https://remote-crm.internal/mcp",
        )
    )
    reg._tools["remote-crm"] = [
        McpToolInfo(
            server_id="remote-crm",
            server_name="Remote CRM MCP",
            name="crm_lookup_account",
            description="Lookup CRM account",
        )
    ]
    router = McpProxyRouter(registry=reg, transport=httpx.MockTransport(handler))
    app = create_app(registry=reg, router=router)
    client = TestClient(app)

    meta_trace_id = "11112222333344445555666677778888"
    meta_parent_id = "aaaabbbbccccdddd"
    resp = client.post(
        "/mcp/aggregate",
        json={
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "crm_lookup_account",
                "arguments": {"account_id": "ACC-42"},
                "_meta": {
                    "traceparent": f"00-{meta_trace_id}-{meta_parent_id}-01",
                    "baggage": "workflow=billing",
                    "custom_key": "preserved",
                },
            },
        },
        headers={"traceparent": "00-99999999999999999999999999999999-1234567890abcdef-01"},
    )
    assert resp.status_code == 200
    assert len(captured) == 1

    outbound_headers = captured[0]["headers"]
    outbound_meta = captured[0]["body"]["params"]["_meta"]
    assert outbound_headers["traceparent"].startswith(f"00-{meta_trace_id}-")
    assert outbound_headers["baggage"] == "workflow=billing"
    assert outbound_meta["traceparent"] == outbound_headers["traceparent"]
    assert outbound_meta["custom_key"] == "preserved"


def test_generated_trace_context_and_denied_span_tracking() -> None:
    client = TestClient(create_app())
    client.post(
        "/api/policies",
        json={
            "id": "deny-eval-guest",
            "name": "Deny guest evals",
            "principal_pattern": "guest",
            "server_pattern": "*",
            "tool_pattern": "*",
            "effect": "deny",
            "mode": "enforced",
            "priority": 500,
        },
    )

    resp = client.post(
        "/mcp/aggregate",
        json={
            "jsonrpc": "2.0",
            "id": 55,
            "method": "tools/call",
            "params": {"name": "attractor_lint_pipeline", "arguments": {"dot_source": "digraph { a -> b; }"}},
        },
        headers={"X-Agent-Principal": "guest"},
    )
    assert resp.status_code == 403
    trace_id = resp.headers.get("X-Trace-Id")
    assert trace_id and len(trace_id) == 32
    assert resp.json()["error"]["data"]["trace_id"] == trace_id

    spans = client.get(f"/api/telemetry/spans?status=denied").json()
    assert len(spans) == 1
    assert spans[0]["trace_id"] == trace_id
    assert spans[0]["source"] == "generated"

    health = client.get("/health").json()
    assert health["telemetry"]["total_spans_recorded"] >= 1
    assert health["telemetry"]["non_ok_buffered_spans"] >= 1
