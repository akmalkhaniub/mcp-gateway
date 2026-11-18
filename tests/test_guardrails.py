"""Tests for MCP Gateway Rate Limiter & Circuit Breaker Guardrails."""

from __future__ import annotations

import time
from fastapi.testclient import TestClient

from gateway.guardrails import CircuitBreakerManager, CircuitState, TokenBucketRateLimiter
from gateway.registry import McpServerRegistry
from gateway.server import create_app


def test_token_bucket_rate_limiter_enforces_429() -> None:
    limiter = TokenBucketRateLimiter(capacity=2.0, refill_rate_per_sec=0.01)
    app = create_app(registry=McpServerRegistry(), rate_limiter=limiter)
    client = TestClient(app)

    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "attractor_list_presets", "arguments": {}},
    }
    headers = {"X-Agent-Principal": "burst-agent"}

    # First 2 calls succeed
    r1 = client.post("/mcp/aggregate", json=payload, headers=headers)
    r2 = client.post("/mcp/aggregate", json=payload, headers=headers)
    assert r1.status_code == 200
    assert r2.status_code == 200

    # 3rd call is throttled with HTTP 429 & JSON-RPC -32004
    r3 = client.post("/mcp/aggregate", json=payload, headers=headers)
    assert r3.status_code == 429
    assert "Retry-After" in r3.headers
    data = r3.json()
    assert data["error"]["code"] == -32004

    # Check guardrail status endpoint
    status_resp = client.get("/api/guardrails/status")
    assert status_resp.status_code == 200
    rl_stats = status_resp.json()["rate_limiter"]
    assert rl_stats["total_allowed"] == 2
    assert rl_stats["total_throttled"] == 1


def test_circuit_breaker_trips_blocks_and_resets() -> None:
    cb = CircuitBreakerManager(failure_threshold=2, recovery_timeout_seconds=60.0)
    app = create_app(registry=McpServerRegistry(), circuit_breaker=cb)
    client = TestClient(app)

    # Trip circuit breaker for attractor-factory
    assert cb.allow_request("attractor-factory") is True
    cb.record_failure("attractor-factory")
    assert cb.status("attractor-factory")["state"] == CircuitState.CLOSED.value
    cb.record_failure("attractor-factory")
    assert cb.status("attractor-factory")["state"] == CircuitState.OPEN.value
    assert cb.allow_request("attractor-factory") is False

    # Proxying to open circuit returns JSON-RPC -32002
    payload = {"jsonrpc": "2.0", "id": 77, "method": "tools/list", "params": {}}
    resp = client.post("/mcp/attractor-factory", json=payload)
    assert resp.status_code == 200
    assert resp.json()["error"]["code"] == -32002

    # Reset via API endpoint
    reset_resp = client.post("/api/guardrails/circuits/attractor-factory/reset")
    assert reset_resp.status_code == 200
    assert reset_resp.json()["circuit"]["state"] == CircuitState.CLOSED.value

    # Subsequent call succeeds
    ok_resp = client.post("/mcp/attractor-factory", json=payload)
    assert ok_resp.status_code == 200
    assert "result" in ok_resp.json()


def test_circuit_breaker_half_open_recovery() -> None:
    cb = CircuitBreakerManager(failure_threshold=1, recovery_timeout_seconds=0.05)
    cb.record_failure("svc-a")
    assert cb.status("svc-a")["state"] == CircuitState.OPEN.value
    assert cb.allow_request("svc-a") is False

    time.sleep(0.08)
    # After cooldown, transitions to HALF_OPEN and permits probe
    assert cb.allow_request("svc-a") is True
    assert cb.status("svc-a")["state"] == CircuitState.HALF_OPEN.value

    # Probe succeeds -> CLOSED
    cb.record_success("svc-a")
    assert cb.status("svc-a")["state"] == CircuitState.CLOSED.value
