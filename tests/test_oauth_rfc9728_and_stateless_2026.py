"""Tests for RFC 9728 OAuth 2.1 Resource Server, RFC 8693 Token Exchange, Stateless 2026-07-28 mode & MCP Tasks."""

from __future__ import annotations

import json
import time

import httpx
from fastapi.testclient import TestClient

from gateway.auth import (
    GatewayOAuthSettings,
    OAuthTokenExchanger,
    mint_hs256_jwt,
    verify_hs256_jwt,
)
from gateway.models import McpServerConfig, McpToolInfo
from gateway.proxy import McpProxyRouter
from gateway.registry import McpServerRegistry
from gateway.server import create_app
from gateway.stateless import ProtocolMode, StatelessHandleManager


def _make_oauth_app(
    *,
    auth_mode: str = "enforced",
    secret: str = "test-gateway-jwt-secret",
    exchange_secret: str = "test-upstream-exchange-secret",
    transport: httpx.AsyncBaseTransport | None = None,
    protocol_mode: ProtocolMode = ProtocolMode.LEGACY_2024,
):
    oauth = GatewayOAuthSettings(
        resource="https://gateway.example.com/mcp",
        authorization_servers=["https://auth.example.com"],
        auth_mode=auth_mode,
        jwt_secret=secret,
        expected_issuer="https://auth.example.com",
    )
    registry = McpServerRegistry()
    router = McpProxyRouter(registry=registry, transport=transport)
    exchanger = OAuthTokenExchanger(
        gateway_resource=oauth.resource,
        exchange_secret=exchange_secret,
    )
    handles = StatelessHandleManager(secret="test-handle-secret")
    app = create_app(
        registry=registry,
        router=router,
        oauth_settings=oauth,
        token_exchanger=exchanger,
        handle_manager=handles,
        default_protocol_mode=protocol_mode,
    )
    return app, oauth, exchanger, handles


def test_rfc9728_metadata_and_bearer_challenges() -> None:
    app, oauth, _, _ = _make_oauth_app(auth_mode="enforced")
    client = TestClient(app)

    meta_resp = client.get("/.well-known/oauth-protected-resource")
    assert meta_resp.status_code == 200
    meta = meta_resp.json()
    assert meta["resource"] == "https://gateway.example.com/mcp"
    assert "https://auth.example.com" in meta["authorization_servers"]
    assert "urn:ietf:params:oauth:grant-type:token-exchange" in meta["token_exchange_grant_types_supported"]

    # Missing token in enforced mode -> 401 + RFC 9728 WWW-Authenticate
    unauth = client.post("/mcp/aggregate", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert unauth.status_code == 401
    www_auth = unauth.headers.get("www-authenticate", "")
    assert 'Bearer resource_metadata="http://testserver/.well-known/oauth-protected-resource"' in www_auth

    # Wrong audience token (token passthrough attempt) -> 401
    wrong_aud = mint_hs256_jwt(
        {
            "iss": "https://auth.example.com",
            "sub": "agent-alice",
            "aud": "https://other-service.example.com/mcp",
            "scope": "mcp:read",
            "exp": int(time.time()) + 300,
        },
        oauth.jwt_secret,
    )
    bad_aud_resp = client.post(
        "/mcp/aggregate",
        headers={"Authorization": f"Bearer {wrong_aud}"},
        json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    )
    assert bad_aud_resp.status_code == 401
    assert "Token passthrough rejected" in bad_aud_resp.json()["error"]["message"]


def test_oauth_scope_filtering_for_tools_list_and_call() -> None:
    app, oauth, _, _ = _make_oauth_app(auth_mode="enforced")
    client = TestClient(app)

    read_only_token = mint_hs256_jwt(
        {
            "iss": "https://auth.example.com",
            "sub": "agent-reader",
            "client_id": "reader-cli",
            "aud": oauth.resource,
            "scope": "mcp:read",
            "exp": int(time.time()) + 300,
        },
        oauth.jwt_secret,
    )

    listed = client.post(
        "/mcp/aggregate",
        headers={"Authorization": f"Bearer {read_only_token}"},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
    )
    assert listed.status_code == 200
    names = {t["name"] for t in listed.json()["result"]["tools"]}
    assert "attractor_lint_pipeline" in names
    assert "attractor_run_pipeline" not in names

    # Attempting to call non-readOnly tool with mcp:read scope fails with 403 insufficient_scope
    denied_call = client.post(
        "/mcp/aggregate",
        headers={"Authorization": f"Bearer {read_only_token}"},
        json={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "attractor_run_pipeline", "arguments": {"dot_source": "digraph G {}"}},
        },
    )
    assert denied_call.status_code == 403
    assert "insufficient_scope" in denied_call.headers.get("www-authenticate", "")


def test_rfc8693_token_exchange_and_confused_deputy_guard() -> None:
    captured_auth_headers: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured_auth_headers.append(request.headers.get("Authorization", ""))
        body = json.loads(request.content.decode("utf-8"))
        return httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "id": body.get("id"),
                "result": {
                    "content": [{"type": "text", "text": "ok"}],
                    "structuredContent": {"upstream": "billing", "ok": True},
                    "isError": False,
                },
            },
        )

    upstream_url = "https://billing-mcp.internal/mcp"
    exchange_secret = "test-upstream-exchange-secret"
    app, oauth, exchanger, _ = _make_oauth_app(
        auth_mode="enforced",
        exchange_secret=exchange_secret,
        transport=httpx.MockTransport(handler),
    )
    app.state.registry.register_server(
        McpServerConfig(
            id="billing-mcp",
            name="Billing MCP",
            transport="http",
            endpoint_url=upstream_url,
        )
    )
    app.state.registry.upsert_server_tools(
        "billing-mcp",
        [
            McpToolInfo(
                server_id="billing-mcp",
                server_name="Billing MCP",
                name="billing_get_invoice",
                description="Fetch invoice record",
                input_schema={"type": "object"},
                annotations={"readOnlyHint": True},
            )
        ],
    )
    client = TestClient(app)

    alice_jwt = mint_hs256_jwt(
        {
            "iss": "https://auth.example.com",
            "sub": "alice@corp",
            "client_id": "shared-web-client",
            "aud": oauth.resource,
            "scope": "mcp:read",
            "exp": int(time.time()) + 300,
        },
        oauth.jwt_secret,
    )
    exchanger.bind_client_consent("shared-web-client", "billing-mcp", "alice@corp")

    res = client.post(
        "/mcp/aggregate",
        headers={"Authorization": f"Bearer {alice_jwt}"},
        json={
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {"name": "billing_get_invoice", "arguments": {"invoice_id": "inv-1"}},
        },
    )
    assert res.status_code == 200
    assert res.json()["result"]["structuredContent"] == {"upstream": "billing", "ok": True}
    assert len(captured_auth_headers) == 1
    upstream_bearer = captured_auth_headers[0].removeprefix("Bearer ").strip()
    assert upstream_bearer != alice_jwt
    exchanged_claims = verify_hs256_jwt(
        upstream_bearer,
        exchange_secret,
        expected_audience=upstream_url,
    )
    assert exchanged_claims["sub"] == "alice@corp"
    assert exchanged_claims["act"] == {"sub": oauth.resource}

    # Confused deputy: another principal using same shared client_id is blocked
    bob_jwt = mint_hs256_jwt(
        {
            "iss": "https://auth.example.com",
            "sub": "bob@corp",
            "client_id": "shared-web-client",
            "aud": oauth.resource,
            "scope": "mcp:read",
            "exp": int(time.time()) + 300,
        },
        oauth.jwt_secret,
    )
    hijack = client.post(
        "/mcp/aggregate",
        headers={"Authorization": f"Bearer {bob_jwt}"},
        json={
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {"name": "billing_get_invoice", "arguments": {"invoice_id": "inv-2"}},
        },
    )
    assert hijack.status_code == 403
    assert "Confused-deputy guard" in hijack.json()["error"]["message"]


def test_stateless_2026_mode_handles_and_mcp_tasks_routing() -> None:
    app, _, _, _ = _make_oauth_app(auth_mode="optional", protocol_mode=ProtocolMode.STATELESS_2026)
    client = TestClient(app)

    init_resp = client.post(
        "/mcp/aggregate",
        headers={"X-Agent-Principal": "worker-1", "MCP-Protocol-Version": "2026-07-28"},
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
    )
    assert init_resp.status_code == 200
    assert "mcp-session-id" not in {k.lower() for k in init_resp.headers.keys()}
    assert init_resp.headers.get("mcp-protocol-version") == "2026-07-28"
    init_body = init_resp.json()
    assert init_body["result"]["protocolVersion"] == "2026-07-28"
    assert init_body["result"]["capabilities"]["stateless"] is True
    handle = init_body["result"]["_meta"]["state_handle"]

    # Valid handle succeeds for same principal
    tasks_get = client.post(
        "/mcp/aggregate",
        headers={"X-Agent-Principal": "worker-1", "MCP-Protocol-Version": "2026-07-28"},
        json={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tasks/get",
            "params": {"taskId": "attractor-factory:task_001", "_meta": {"state_handle": handle}},
        },
    )
    assert tasks_get.status_code == 200
    assert tasks_get.json()["result"]["task"]["taskId"] == "task_001"
    assert tasks_get.json()["result"]["task"]["serverId"] == "attractor-factory"

    # Cross-principal replay of handle is rejected (handle != auth)
    replay = client.post(
        "/mcp/aggregate",
        headers={"X-Agent-Principal": "attacker-2", "MCP-Protocol-Version": "2026-07-28"},
        json={
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tasks/cancel",
            "params": {"taskId": "attractor-factory:task_001", "_meta": {"state_handle": handle}},
        },
    )
    assert replay.status_code == 403
    assert "principal mismatch" in replay.json()["error"]["message"]
