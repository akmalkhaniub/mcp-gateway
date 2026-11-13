"""Semantic in-memory caching engine for MCP Gateway."""

from __future__ import annotations

import hashlib
import json
import threading
import time
from typing import Any


class McpResponseCache:
    """Thread-safe semantic response cache with TTL for deterministic MCP tools."""

    CACHEABLE_PREFIXES = ("lint", "get", "list", "parse", "read", "describe", "check", "inspect", "search", "fetch")

    def __init__(self, default_ttl_seconds: float = 60.0) -> None:
        self.default_ttl = default_ttl_seconds
        self._cache: dict[str, tuple[float, dict[str, Any]]] = {}
        self._lock = threading.RLock()
        self.hits: int = 0
        self.misses: int = 0

    @classmethod
    def is_cacheable(cls, tool_name: str) -> bool:
        """Determines if a tool is safe to cache based on semantic naming conventions."""
        lower = tool_name.lower()
        # Explicit known tools
        if any(lower.startswith(p) for p in cls.CACHEABLE_PREFIXES):
            return True
        # Under score or hyphen separated prefixes: e.g. attractor_lint_pipeline
        parts = lower.replace("-", "_").split("_")
        return any(p in cls.CACHEABLE_PREFIXES for p in parts)

    def _make_key(self, server_id: str, tool_name: str, arguments: dict[str, Any]) -> str:
        canonical_args = json.dumps(arguments, sort_keys=True, separators=(",", ":"))
        raw = f"{server_id}::{tool_name}::{canonical_args}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def get(self, server_id: str, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any] | None:
        if not self.is_cacheable(tool_name):
            return None

        key = self._make_key(server_id, tool_name, arguments)
        now = time.monotonic()
        with self._lock:
            if key in self._cache:
                expires_at, data = self._cache[key]
                if now < expires_at:
                    self.hits += 1
                    # Return copy to prevent mutations
                    cached_copy = json.loads(json.dumps(data))
                    return cached_copy
                # Expired
                del self._cache[key]
            self.misses += 1
            return None

    def set(self, server_id: str, tool_name: str, arguments: dict[str, Any], result: dict[str, Any], ttl: float | None = None) -> None:
        if not self.is_cacheable(tool_name):
            return

        key = self._make_key(server_id, tool_name, arguments)
        expires_at = time.monotonic() + (ttl if ttl is not None else self.default_ttl)
        with self._lock:
            self._cache[key] = (expires_at, result)

    def clear(self) -> int:
        with self._lock:
            count = len(self._cache)
            self._cache.clear()
            return count

    def stats(self) -> dict[str, Any]:
        with self._lock:
            total = self.hits + self.misses
            ratio = round((self.hits / total * 100), 2) if total > 0 else 0.0
            return {
                "hits": self.hits,
                "misses": self.misses,
                "total_requests": total,
                "hit_ratio_pct": ratio,
                "cached_entries": len(self._cache),
            }
