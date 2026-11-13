"""Registry managing upstream MCP servers and discovered tools."""

from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from typing import Any

from .models import McpServerConfig, McpServerStats, McpToolInfo, ServerHealth


class McpServerRegistry:
    """Thread-safe registry for upstream MCP servers and aggregated tool catalog."""

    def __init__(self) -> None:
        self._servers: dict[str, McpServerConfig] = {}
        self._stats: dict[str, McpServerStats] = {}
        self._tools: dict[str, list[McpToolInfo]] = {}
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
        self._tools["attractor-factory"] = [
            McpToolInfo(
                server_id="attractor-factory",
                server_name=attractor_cfg.name,
                name="attractor_lint_pipeline",
                description="Lint and validate a Graphviz DOT software factory pipeline against 13 specification rules.",
                input_schema={"type": "object", "properties": {"dot_source": {"type": "string"}}, "required": ["dot_source"]},
            ),
            McpToolInfo(
                server_id="attractor-factory",
                server_name=attractor_cfg.name,
                name="attractor_run_pipeline",
                description="Execute an Attractor software factory pipeline against a target workspace.",
                input_schema={"type": "object", "properties": {"dot_source": {"type": "string"}, "workspace": {"type": "string"}}, "required": ["dot_source"]},
            ),
            McpToolInfo(
                server_id="attractor-factory",
                server_name=attractor_cfg.name,
                name="attractor_list_presets",
                description="List built-in Software Factory blueprints and preset pipelines.",
                input_schema={"type": "object", "properties": {}},
            ),
        ]
        self._stats["attractor-factory"] = McpServerStats(
            server_id="attractor-factory",
            health=ServerHealth.HEALTHY,
            total_calls=12,
            avg_latency_ms=18.5,
            last_checked=datetime.now(timezone.utc).isoformat(),
            discovered_tools_count=3,
        )

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
            return config

    def remove_server(self, server_id: str) -> bool:
        with self._lock:
            if server_id in self._servers:
                del self._servers[server_id]
                self._stats.pop(server_id, None)
                self._tools.pop(server_id, None)
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

    def list_all_tools(self) -> list[McpToolInfo]:
        with self._lock:
            all_tools: list[McpToolInfo] = []
            for s_id, cfg in self._servers.items():
                if cfg.enabled:
                    all_tools.extend(self._tools.get(s_id, []))
            return all_tools

    def find_tool(self, tool_name: str) -> tuple[McpServerConfig, McpToolInfo] | None:
        with self._lock:
            for s_id, tools in self._tools.items():
                cfg = self._servers.get(s_id)
                if not cfg or not cfg.enabled:
                    continue
                for t in tools:
                    if t.name == tool_name:
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
