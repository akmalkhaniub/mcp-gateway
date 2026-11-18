"""Runtime guardrails: Token-Bucket Rate Limiter, Circuit Breaker & Audit Log."""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any


class CircuitState(StrEnum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class _CircuitRecord:
    state: CircuitState = CircuitState.CLOSED
    consecutive_failures: int = 0
    total_trips: int = 0
    opened_at: float | None = None
    last_failure_at: str | None = None


class CircuitBreakerManager:
    """Per-upstream circuit breaker preventing cascading failures."""

    def __init__(self, failure_threshold: int = 3, recovery_timeout_seconds: float = 30.0) -> None:
        self.failure_threshold = failure_threshold
        self.recovery_timeout_seconds = recovery_timeout_seconds
        self._circuits: dict[str, _CircuitRecord] = {}
        self._lock = threading.RLock()

    def _get(self, server_id: str) -> _CircuitRecord:
        if server_id not in self._circuits:
            self._circuits[server_id] = _CircuitRecord()
        return self._circuits[server_id]

    def allow_request(self, server_id: str) -> bool:
        with self._lock:
            rec = self._get(server_id)
            if rec.state == CircuitState.CLOSED:
                return True
            if rec.state == CircuitState.OPEN:
                if rec.opened_at is not None and (time.monotonic() - rec.opened_at) >= self.recovery_timeout_seconds:
                    rec.state = CircuitState.HALF_OPEN
                    return True
                return False
            # HALF_OPEN permits probe request
            return True

    def record_success(self, server_id: str) -> None:
        with self._lock:
            rec = self._get(server_id)
            rec.consecutive_failures = 0
            rec.state = CircuitState.CLOSED
            rec.opened_at = None

    def record_failure(self, server_id: str) -> CircuitState:
        with self._lock:
            rec = self._get(server_id)
            rec.consecutive_failures += 1
            rec.last_failure_at = datetime.now(timezone.utc).isoformat()
            if rec.state == CircuitState.HALF_OPEN or rec.consecutive_failures >= self.failure_threshold:
                rec.state = CircuitState.OPEN
                rec.opened_at = time.monotonic()
                rec.total_trips += 1
            return rec.state

    def reset(self, server_id: str) -> bool:
        with self._lock:
            if server_id in self._circuits:
                self._circuits[server_id] = _CircuitRecord()
                return True
            self._circuits[server_id] = _CircuitRecord()
            return True

    def status(self, server_id: str) -> dict[str, Any]:
        with self._lock:
            rec = self._get(server_id)
            retry_in = 0.0
            if rec.state == CircuitState.OPEN and rec.opened_at is not None:
                remaining = self.recovery_timeout_seconds - (time.monotonic() - rec.opened_at)
                retry_in = round(max(0.0, remaining), 2)
            return {
                "server_id": server_id,
                "state": rec.state.value,
                "consecutive_failures": rec.consecutive_failures,
                "total_trips": rec.total_trips,
                "retry_in_seconds": retry_in,
                "last_failure_at": rec.last_failure_at,
            }

    def all_statuses(self) -> dict[str, dict[str, Any]]:
        with self._lock:
            return {sid: self.status(sid) for sid in self._circuits}


@dataclass
class _Bucket:
    tokens: float
    last_refill: float


class TokenBucketRateLimiter:
    """Thread-safe token bucket rate limiter keyed by client identity."""

    def __init__(self, capacity: float = 60.0, refill_rate_per_sec: float = 2.0) -> None:
        self.capacity = capacity
        self.refill_rate = refill_rate_per_sec
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.RLock()
        self.total_allowed: int = 0
        self.total_throttled: int = 0

    def consume(self, client_id: str, tokens: float = 1.0) -> tuple[bool, float]:
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets.get(client_id)
            if bucket is None:
                bucket = _Bucket(tokens=self.capacity, last_refill=now)
                self._buckets[client_id] = bucket
            else:
                elapsed = max(0.0, now - bucket.last_refill)
                bucket.tokens = min(self.capacity, bucket.tokens + elapsed * self.refill_rate)
                bucket.last_refill = now

            if bucket.tokens >= tokens:
                bucket.tokens -= tokens
                self.total_allowed += 1
                return True, 0.0

            self.total_throttled += 1
            deficit = tokens - bucket.tokens
            retry_after = round(deficit / self.refill_rate, 2) if self.refill_rate > 0 else 1.0
            return False, retry_after

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "capacity": self.capacity,
                "refill_rate_per_sec": self.refill_rate,
                "active_clients": len(self._buckets),
                "total_allowed": self.total_allowed,
                "total_throttled": self.total_throttled,
            }


class AuditLogStore:
    """In-memory ring-buffer audit log of MCP invocations."""

    def __init__(self, max_entries: int = 200) -> None:
        self._events: deque[dict[str, Any]] = deque(maxlen=max_entries)
        self._lock = threading.RLock()

    def record(
        self,
        *,
        server_id: str,
        method: str,
        tool_name: str | None = None,
        client_id: str = "anonymous",
        cached: bool = False,
        latency_ms: float = 0.0,
        status: str = "ok",
        error_message: str | None = None,
    ) -> dict[str, Any]:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "server_id": server_id,
            "method": method,
            "tool_name": tool_name,
            "client_id": client_id,
            "cached": cached,
            "latency_ms": round(latency_ms, 2),
            "status": status,
            "error_message": error_message,
        }
        with self._lock:
            self._events.appendleft(entry)
        return entry

    def list_events(self, limit: int = 50, server_id: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            events = list(self._events)
            if server_id:
                events = [e for e in events if e["server_id"] == server_id]
            return events[:limit]

    def clear(self) -> int:
        with self._lock:
            count = len(self._events)
            self._events.clear()
            return count
