"""Tests for MCP Gateway & Reverse Proxy."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from gateway.models import McpServerConfig, ServerTransport
from gateway.registry import McpServerRegistry
from gateway.server import create_app


@pytest.fixture
def client() -> TestClient:
    reg = McpServerRegistry()
    app = create_app(registry=reg)
    return TestClient(app)


def test_gateway_health(client: TestClient) -> None:
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["service"] == "mcp-gateway"
    assert data["servers_count"] >= 1
    assert data["total_tools"] >= 3


def test_list_and_register_server(client: TestClient) -> None:
    # 1. List initial servers
    list_resp = client.get("/api/servers")
    assert list_resp.status_code == 200
    servers = list_resp.json()
    assert any(s["id"] == "attractor-factory" for s in servers)

    # 2. Register custom upstream server
    new_server = {
        "id": "code-analyzer",
        "name": "Code Analysis MCP",
        "description": "Static code analysis tools",
        "transport": "http",
        "endpoint_url": "http://127.0.0.1:9090/mcp",
        "enabled": True,
    }
    reg_resp = client.post("/api/servers", json=new_server)
    assert reg_resp.status_code == 200
    assert reg_resp.json()["status"] == "registered"

    # 3. Verify it is listed
    updated_resp = client.get("/api/servers")
    assert any(s["id"] == "code-analyzer" for s in updated_resp.json())

    # 4. Remove server
    del_resp = client.delete("/api/servers/code-analyzer")
    assert del_resp.status_code == 200
    assert del_resp.json()["status"] == "removed"


def test_list_all_tools(client: TestClient) -> None:
    resp = client.get("/api/tools")
    assert resp.status_code == 200
    tools = resp.json()
    tool_names = [t["name"] for t in tools]
    assert "attractor_lint_pipeline" in tool_names
    assert "attractor_run_pipeline" in tool_names


def test_proxy_to_upstream_server(client: TestClient) -> None:
    # Test tools/list via proxy
    list_payload = {"jsonrpc": "2.0", "id": 101, "method": "tools/list", "params": {}}
    resp = client.post("/mcp/attractor-factory", json=list_payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["jsonrpc"] == "2.0"
    assert data["id"] == 101
    assert "tools" in data["result"]

    # Test tools/call via proxy
    call_payload = {
        "jsonrpc": "2.0",
        "id": 102,
        "method": "tools/call",
        "params": {"name": "attractor_lint_pipeline", "arguments": {"dot_source": "digraph { a -> b; }"}},
    }
    call_resp = client.post("/mcp/attractor-factory", json=call_payload)
    assert call_resp.status_code == 200
    cdata = call_resp.json()
    assert cdata["id"] == 102
    assert "content" in cdata["result"]


def test_aggregate_mcp_protocol(client: TestClient) -> None:
    # 1. initialize
    init_payload = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    init_resp = client.post("/mcp/aggregate", json=init_payload)
    assert init_resp.status_code == 200
    assert init_resp.json()["result"]["serverInfo"]["name"] == "mcp-gateway-aggregator"

    # 2. ping
    ping_resp = client.post("/mcp/aggregate", json={"jsonrpc": "2.0", "id": 2, "method": "ping"})
    assert ping_resp.status_code == 200
    assert ping_resp.json()["result"] == {}

    # 3. tools/list
    tools_resp = client.post("/mcp/aggregate", json={"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
    assert tools_resp.status_code == 200
    tools = tools_resp.json()["result"]["tools"]
    assert len(tools) >= 3

    # 4. tools/call dynamically routed to attractor-factory
    exec_payload = {
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {"name": "attractor_lint_pipeline", "arguments": {"dot_source": "digraph Pipeline { start -> end; }"}},
    }
    exec_resp = client.post("/mcp/aggregate", json=exec_payload)
    assert exec_resp.status_code == 200
    exec_data = exec_resp.json()
    assert exec_data["id"] == 4
    assert "content" in exec_data["result"]


def test_aggregate_mcp_tool_not_found(client: TestClient) -> None:
    exec_payload = {
        "jsonrpc": "2.0",
        "id": 999,
        "method": "tools/call",
        "params": {"name": "non_existent_tool_12345", "arguments": {}},
    }
    resp = client.post("/mcp/aggregate", json=exec_payload)
    assert resp.status_code == 200
    data = resp.json()
    assert "error" in data
    assert data["error"]["code"] == -32601


def test_dashboard_ui_served(client: TestClient) -> None:
    resp = client.get("/")
    assert resp.status_code == 200
    assert "MCP Gateway" in resp.text


def test_semantic_response_cache(client: TestClient) -> None:
    # 1. Initial tool call (cache miss)
    payload = {
        "jsonrpc": "2.0",
        "id": 201,
        "method": "tools/call",
        "params": {"name": "attractor_lint_pipeline", "arguments": {"dot_source": "digraph CachedPipeline { start -> end; }"}},
    }
    resp1 = client.post("/mcp/aggregate", json=payload)
    assert resp1.status_code == 200
    assert resp1.json()["result"].get("_cached") is None or not resp1.json()["result"].get("_cached")

    # 2. Second tool call with identical arguments (cache hit!)
    resp2 = client.post("/mcp/aggregate", json=payload)
    assert resp2.status_code == 200
    assert resp2.json()["result"].get("_cached") is True

    # 3. Verify cache stats
    stats_resp = client.get("/api/cache/stats")
    assert stats_resp.status_code == 200
    stats = stats_resp.json()
    assert stats["hits"] >= 1
    assert stats["cached_entries"] >= 1


def test_cache_clear_endpoint(client: TestClient) -> None:
    clear_resp = client.post("/api/cache/clear")
    assert clear_resp.status_code == 200
    assert clear_resp.json()["status"] == "cleared"

    stats_resp = client.get("/api/cache/stats")
    assert stats_resp.json()["cached_entries"] == 0


def test_health_prober_endpoint(client: TestClient) -> None:
    probe_resp = client.post("/api/servers/probe")
    assert probe_resp.status_code == 200
    results = probe_resp.json()
    assert isinstance(results, list)
    assert len(results) >= 1
    assert any(r["server_id"] == "attractor-factory" and r["status"] == "healthy" for r in results)
