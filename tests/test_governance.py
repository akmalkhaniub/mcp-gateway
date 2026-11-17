"""Tests for Principal Access Boundaries, HITL approval tokens, and Audit Trail in MCP Gateway."""

from __future__ import annotations

from fastapi.testclient import TestClient

from gateway.policy import EnforcementMode, McpGovernanceEngine, PolicyEffect, ToolAccessPolicy
from gateway.registry import McpServerRegistry
from gateway.server import create_app


def make_client() -> TestClient:
    reg = McpServerRegistry()
    gov = McpGovernanceEngine(approval_secret="test-secret-key-for-hmac")
    app = create_app(registry=reg, governance=gov)
    return TestClient(app)


def test_policy_crud_and_health_counts() -> None:
    client = make_client()
    policy = {
        "id": "deny-run-untrusted",
        "name": "Block pipeline execution for untrusted agents",
        "principal_pattern": "principal://agents.global.org-demo/*",
        "server_pattern": "attractor-factory",
        "tool_pattern": "attractor_run_*",
        "effect": "deny",
        "mode": "enforced",
        "priority": 200,
    }
    res = client.post("/api/policies", json=policy)
    assert res.status_code == 200
    assert res.json()["status"] == "saved"

    policies = client.get("/api/policies").json()
    assert len(policies) == 1
    assert policies[0]["id"] == "deny-run-untrusted"

    health = client.get("/health").json()
    assert health["governance"]["policies_count"] == 1

    del_res = client.delete("/api/policies/deny-run-untrusted")
    assert del_res.status_code == 200
    assert client.get("/api/policies").json() == []


def test_enforced_deny_blocks_tool_and_prevents_cache_leak() -> None:
    client = make_client()
    # First, an authorized principal warms the semantic cache on a cacheable tool
    authorized_principal = "principal://agents.global.org-1/resources/reasoningEngines/trusted"
    blocked_principal = "principal://agents.global.org-1/resources/reasoningEngines/untrusted"

    client.post(
        "/api/policies",
        json={
            "id": "deny-untrusted-lint",
            "name": "Block untrusted principal from lint",
            "principal_pattern": "*untrusted*",
            "server_pattern": "*",
            "tool_pattern": "attractor_lint_*",
            "effect": "deny",
            "mode": "enforced",
            "priority": 300,
        },
    )

    call_body = {
        "jsonrpc": "2.0",
        "id": 10,
        "method": "tools/call",
        "params": {"name": "attractor_lint_pipeline", "arguments": {"dot_source": "digraph G { a -> b; }"}},
    }

    ok_resp = client.post(
        "/mcp/aggregate",
        json=call_body,
        headers={"X-Agent-Principal": authorized_principal},
    )
    assert ok_resp.status_code == 200
    assert "result" in ok_resp.json()

    # Unauthorized principal MUST be denied BEFORE reading the warmed cache
    deny_resp = client.post(
        "/mcp/aggregate",
        json=call_body,
        headers={"X-Agent-Principal": blocked_principal},
    )
    assert deny_resp.status_code == 403
    err = deny_resp.json()["error"]
    assert err["code"] == -32003
    assert err["data"]["matched_policy_id"] == "deny-untrusted-lint"

    # Direct server proxy route /mcp/{server_id} enforces the same policy
    direct_deny = client.post(
        "/mcp/attractor-factory",
        json=call_body,
        headers={"X-Agent-Principal": blocked_principal},
    )
    assert direct_deny.status_code == 403

    # Audit log captures allowed + 2 denied events
    logs = client.get("/api/audit/logs?decision=denied").json()
    assert len(logs) == 2
    assert all(entry["principal"] == blocked_principal for entry in logs)


def test_dry_run_mode_allows_but_audits() -> None:
    client = make_client()
    client.post(
        "/api/policies",
        json={
            "id": "dryrun-run-pipeline",
            "name": "Audit pipeline execution",
            "principal_pattern": "*",
            "server_pattern": "attractor-factory",
            "tool_pattern": "attractor_run_pipeline",
            "effect": "deny",
            "mode": "dry_run",
            "priority": 150,
        },
    )

    resp = client.post(
        "/mcp/aggregate",
        json={
            "jsonrpc": "2.0",
            "id": 22,
            "method": "tools/call",
            "params": {"name": "attractor_run_pipeline", "arguments": {"dot_source": "digraph { a -> b; }"}},
        },
        headers={"X-Agent-Principal": "principal://agents.global.org-1/claims"},
    )
    assert resp.status_code == 200
    assert resp.headers.get("X-MCP-Policy-Audit") == "DRY_RUN_WOULD_DENY"
    assert "result" in resp.json()

    logs = client.get("/api/audit/logs?decision=dry_run_would_deny").json()
    assert len(logs) == 1
    assert logs[0]["policy_id"] == "dryrun-run-pipeline"


def test_hitl_approval_token_flow_and_tamper_rejection() -> None:
    client = make_client()
    principal = "principal://agents.global.org-1/claims-settler"
    client.post(
        "/api/policies",
        json={
            "id": "hitl-pipeline-exec",
            "name": "Require HITL approval for pipeline execution",
            "principal_pattern": principal,
            "server_pattern": "attractor-factory",
            "tool_pattern": "attractor_run_pipeline",
            "effect": "allow",
            "mode": "enforced",
            "require_approval": True,
            "priority": 250,
        },
    )

    rpc = {
        "jsonrpc": "2.0",
        "id": 31,
        "method": "tools/call",
        "params": {"name": "attractor_run_pipeline", "arguments": {"dot_source": "digraph { a -> b; }"}},
    }

    # Missing token -> 403 with require_approval=True
    missing_resp = client.post("/mcp/aggregate", json=rpc, headers={"X-Agent-Principal": principal})
    assert missing_resp.status_code == 403
    assert missing_resp.json()["error"]["data"]["require_approval"] is True

    # Issue scoped HITL approval token
    tok_resp = client.post(
        "/api/policies/approval-token",
        json={
            "principal": principal,
            "server_id": "attractor-factory",
            "tool_name": "attractor_run_pipeline",
            "ttl_seconds": 120,
        },
    )
    assert tok_resp.status_code == 200
    token = tok_resp.json()["approval_token"]

    # Tampered token rejected
    tampered_resp = client.post(
        "/mcp/aggregate",
        json=rpc,
        headers={"X-Agent-Principal": principal, "X-Approval-Token": token + "tamper"},
    )
    assert tampered_resp.status_code == 403

    # Wrong principal rejected even with valid token
    client.post(
        "/api/policies",
        json={
            "id": "hitl-any",
            "name": "Require HITL for all",
            "principal_pattern": "*",
            "server_pattern": "attractor-factory",
            "tool_pattern": "attractor_run_pipeline",
            "effect": "allow",
            "mode": "enforced",
            "require_approval": True,
            "priority": 100,
        },
    )
    wrong_sub_resp = client.post(
        "/mcp/aggregate",
        json=rpc,
        headers={"X-Agent-Principal": "principal://agents.global.org-1/other", "X-Approval-Token": token},
    )
    assert wrong_sub_resp.status_code == 403

    # Valid token + matching principal succeeds
    ok_resp = client.post(
        "/mcp/aggregate",
        json=rpc,
        headers={"X-Agent-Principal": principal, "X-Approval-Token": token},
    )
    assert ok_resp.status_code == 200
    assert "result" in ok_resp.json()


def test_streamable_http_session_and_notifications_initialized() -> None:
    client = make_client()
    init_resp = client.post(
        "/mcp/aggregate",
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
    )
    assert init_resp.status_code == 200
    session_id = init_resp.headers.get("Mcp-Session-Id")
    assert session_id and session_id.startswith("mcp-")

    notif_resp = client.post(
        "/mcp/aggregate",
        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        headers={"Mcp-Session-Id": session_id},
    )
    assert notif_resp.status_code == 202
    assert notif_resp.headers.get("Mcp-Session-Id") == session_id
