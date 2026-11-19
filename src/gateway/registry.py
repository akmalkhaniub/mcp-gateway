"""Registry managing upstream MCP servers and discovered tools."""

from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any

from .models import McpServerConfig, McpServerStats, McpToolInfo, ServerHealth

POISONING_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)ignore\s+(all\s+)?previous\s+instructions"),
    re.compile(r"(?i)<important>.*?</important>", re.DOTALL),
    re.compile(r"(?i)\b(exfiltrate|send\s+secrets?|dump\s+env|read\s+/etc/passwd)\b"),
    re.compile(r"[\u200b\u200c\u200d\ufeff]"),
]


def compute_tool_digest(tool: McpToolInfo) -> str:
    """Compute canonical SHA-256 digest over tool metadata for rug-pull detection."""
    payload = {
        "name": tool.name,
        "description": tool.description,
        "inputSchema": tool.input_schema,
        "annotations": tool.annotations,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def detect_tool_poisoning(description: str) -> str | None:
    """Scan tool description for hidden prompt-injection or zero-width smuggling directives."""
    for pat in POISONING_PATTERNS:
        match = pat.search(description)
        if match:
            return f"Tool poisoning directive detected ({match.group(0)[:40]!r})"
    return None


class McpServerRegistry:
    """Thread-safe registry for upstream MCP servers and aggregated tool catalog."""

    def __init__(self) -> None:
        self._servers: dict[str, McpServerConfig] = {}
        self._stats: dict[str, McpServerStats] = {}
        self._tools: dict[str, list[McpToolInfo]] = {}
        self._pinned_digests: dict[str, str] = {}
        self._notifications: deque[dict[str, Any]] = deque(maxlen=200)
        self._lock = threading.RLock()
        self._init_defaults()

    def _init_defaults(self) -> None:
        # Pre-register local Attractor Factory MCP server
        attractor_cfg = McpServerConfig(
            id="attractor-factory",
            name="Attractor Software Factory MCP",
            description="Software Factory DOT pipeline execution, spec linter & agent runner",
            transport="http",
            endpoint_url="http://127.0.0.1:8000/mcp",
            enabled=True,
        )
        self.register_server(attractor_cfg)

        # Mock tools for the pre-registered Attractor server
        self.upsert_server_tools(
            "attractor-factory",
            [
                McpToolInfo(
                    server_id="attractor-factory",
                    server_name=attractor_cfg.name,
                    name="attractor_lint_pipeline",
                    description="Lint and validate a Graphviz DOT software factory pipeline against 13 specification rules.",
                    input_schema={"type": "object", "properties": {"dot_source": {"type": "string"}}, "required": ["dot_source"]},
                    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
                ),
                McpToolInfo(
                    server_id="attractor-factory",
                    server_name=attractor_cfg.name,
                    name="attractor_run_pipeline",
                    description="Execute an Attractor software factory pipeline against a target workspace.",
                    input_schema={"type": "object", "properties": {"dot_source": {"type": "string"}, "workspace": {"type": "string"}}, "required": ["dot_source"]},
                    annotations={"readOnlyHint": False, "destructiveHint": False},
                ),
                McpToolInfo(
                    server_id="attractor-factory",
                    server_name=attractor_cfg.name,
                    name="attractor_list_presets",
                    description="List built-in Software Factory blueprints and preset pipelines.",
                    input_schema={"type": "object", "properties": {}},
                    annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True},
                ),
            ],
        )
        self._stats["attractor-factory"] = McpServerStats(
            server_id="attractor-factory",
            health=ServerHealth.HEALTHY,
            total_calls=12,
            avg_latency_ms=18.5,
            last_checked=datetime.now(timezone.utc).isoformat(),
            discovered_tools_count=3,
        )

    def emit_tools_list_changed(self, reason: str, server_id: str | None = None) -> None:
        with self._lock:
            self._notifications.append(
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/tools/list_changed",
                    "params": {
                        "reason": reason,
                        "server_id": server_id,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    },
                }
            )

    def list_notifications(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._notifications)

    def upsert_server_tools(self, server_id: str, tools: list[McpToolInfo]) -> list[McpToolInfo]:
        """Pin tool SHA-256 digests and quarantine poisoned or rug-pulled definitions."""
        with self._lock:
            processed: list[McpToolInfo] = []
            for tool in tools:
                digest = compute_tool_digest(tool)
                pin_key = f"{server_id}:{tool.name}"
                pinned = self._pinned_digests.get(pin_key)
                poison_reason = detect_tool_poisoning(tool.description)

                quarantined = False
                q_reason = ""
                if poison_reason:
                    quarantined = True
                    q_reason = poison_reason
                elif pinned is not None and pinned != digest:
                    quarantined = True
                    q_reason = f"Rug pull detected: pinned digest {pinned[:12]} mutated to {digest[:12]}."
                elif pinned is None:
                    self._pinned_digests[pin_key] = digest

                processed.append(
                    tool.model_copy(
                        update={
                            "definition_digest": digest,
                            "quarantined": quarantined,
                            "quarantine_reason": q_reason,
                        }
                    )
                )
            self._tools[server_id] = processed
            if server_id in self._stats:
                self._stats[server_id].discovered_tools_count = sum(1 for t in processed if not t.quarantined)
            self.emit_tools_list_changed("tools_updated", server_id=server_id)
            return processed

    def register_server(self, config: McpServerConfig) -> McpServerConfig:
        with self._lock:
            self._servers[config.id] = config
            if config.id not in self._stats:
                self._stats[config.id] = McpServerStats(
                    server_id=config.id,
                    health=ServerHealth.HEALTHY,
                    last_checked=datetime.now(timezone.utc).isoformat(),
                )
            if config.id not in self._tools:
                self._tools[config.id] = []
            self.emit_tools_list_changed("server_registered", server_id=config.id)
            return config

    def remove_server(self, server_id: str) -> bool:
        with self._lock:
            if server_id in self._servers:
                del self._servers[server_id]
                self._stats.pop(server_id, None)
                self._tools.pop(server_id, None)
                for k in [key for key in self._pinned_digests if key.startswith(f"{server_id}:")]:
                    self._pinned_digests.pop(k, None)
                self.emit_tools_list_changed("server_removed", server_id=server_id)
                return True
            return False

    def get_server(self, server_id: str) -> McpServerConfig | None:
        with self._lock:
            return self._servers.get(server_id)

    def list_servers(self) -> list[dict[str, Any]]:
        with self._lock:
            results = []
            for s_id, s_cfg in self._servers.items():
                stats = self._stats.get(s_id, McpServerStats(server_id=s_id))
                results.append(
                    {
                        **s_cfg.model_dump(),
                        "health": stats.health.value,
                        "total_calls": stats.total_calls,
                        "error_calls": stats.error_calls,
                        "avg_latency_ms": stats.avg_latency_ms,
                        "last_checked": stats.last_checked,
                        "tool_count": len(self._tools.get(s_id, [])),
                    }
                )
            return results

    def list_all_tools(self, *, include_quarantined: bool = False) -> list[McpToolInfo]:
        with self._lock:
            all_tools: list[McpToolInfo] = []
            for s_id, cfg in self._servers.items():
                if cfg.enabled:
                    for tool in self._tools.get(s_id, []):
                        if include_quarantined or not tool.quarantined:
                            all_tools.append(tool)
            return all_tools

    def find_tool(self, tool_name: str) -> tuple[McpServerConfig, McpToolInfo] | None:
        with self._lock:
            for s_id, tools in self._tools.items():
                cfg = self._servers.get(s_id)
                if not cfg or not cfg.enabled:
                    continue
                for t in tools:
                    if t.name == tool_name and not t.quarantined:
                        return cfg, t
            return None

    def record_call(self, server_id: str, latency_ms: float, is_error: bool = False) -> None:
        with self._lock:
            stats = self._stats.get(server_id)
            if not stats:
                return
            stats.total_calls += 1
            if is_error:
                stats.error_calls += 1
            stats.avg_latency_ms = round((stats.avg_latency_ms * 0.8) + (latency_ms * 0.2), 2)
            stats.last_checked = datetime.now(timezone.utc).isoformat()
