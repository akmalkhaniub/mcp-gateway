"""Data models for MCP Gateway & Reverse Proxy."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ServerTransport(StrEnum):
    STDIO = "stdio"
    HTTP = "http"
    SSE = "sse"


class ServerHealth(StrEnum):
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    OFFLINE = "offline"
    UNKNOWN = "unknown"


class McpServerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    id: str
    name: str
    description: str = ""
    transport: ServerTransport = ServerTransport.HTTP
    endpoint_url: str | None = None
    command: str | None = None
    args: list[str] = Field(default_factory=list)
    headers: dict[str, str] = Field(default_factory=dict)
    enabled: bool = True
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class McpToolInfo(BaseModel):
    server_id: str
    server_name: str
    name: str
    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict)
    annotations: dict[str, Any] = Field(default_factory=dict)
    definition_digest: str = ""
    quarantined: bool = False
    quarantine_reason: str = ""


class McpServerStats(BaseModel):
    server_id: str
    health: ServerHealth = ServerHealth.UNKNOWN
    total_calls: int = 0
    error_calls: int = 0
    avg_latency_ms: float = 0.0
    last_checked: str | None = None
    discovered_tools_count: int = 0
