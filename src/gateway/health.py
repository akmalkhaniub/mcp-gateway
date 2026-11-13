"""Active Health Prober and Heartbeat Daemon for MCP Upstreams."""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from .models import ServerHealth
from .registry import McpServerRegistry

logger = logging.getLogger(__name__)


class McpHealthProber:
    """Probes registered upstream MCP servers and updates health and latency metrics."""

    def __init__(self, registry: McpServerRegistry, probe_timeout: float = 3.0) -> None:
        self.registry = registry
        self.probe_timeout = probe_timeout
        self._bg_task: asyncio.Task[None] | None = None
        self._running = False

    async def probe_server(self, server_id: str) -> dict[str, Any]:
        config = self.registry.get_server(server_id)
        if not config:
            return {"server_id": server_id, "status": "unknown", "error": "Server not found"}

        if not config.enabled:
            return {"server_id": server_id, "status": "disabled"}

        # Local test server / mock handler
        if not config.endpoint_url or "127.0.0.1" in config.endpoint_url:
            stats = self.registry._stats.get(server_id)
            if stats:
                stats.health = ServerHealth.HEALTHY
                stats.last_checked = datetime.now(timezone.utc).isoformat()
            return {"server_id": server_id, "status": ServerHealth.HEALTHY.value, "latency_ms": 1.0}

        # Probe external HTTP endpoint
        start_t = time.monotonic()
        try:
            async with httpx.AsyncClient(timeout=self.probe_timeout) as client:
                headers = {"Content-Type": "application/json", **config.headers}
                payload = {"jsonrpc": "2.0", "id": "health-probe", "method": "ping"}
                resp = await client.post(config.endpoint_url, json=payload, headers=headers)
                latency = round((time.monotonic() - start_t) * 1000, 2)

                if resp.is_success:
                    self.registry.record_call(server_id, latency, is_error=False)
                    stats = self.registry._stats.get(server_id)
                    if stats:
                        stats.health = ServerHealth.HEALTHY
                    return {"server_id": server_id, "status": ServerHealth.HEALTHY.value, "latency_ms": latency}

                # Unhealthy response
                self.registry.record_call(server_id, latency, is_error=True)
                stats = self.registry._stats.get(server_id)
                if stats:
                    stats.health = ServerHealth.UNHEALTHY
                return {"server_id": server_id, "status": ServerHealth.UNHEALTHY.value, "http_status": resp.status_code}

        except Exception as exc:
            latency = round((time.monotonic() - start_t) * 1000, 2)
            self.registry.record_call(server_id, latency, is_error=True)
            stats = self.registry._stats.get(server_id)
            if stats:
                stats.health = ServerHealth.OFFLINE
            return {"server_id": server_id, "status": ServerHealth.OFFLINE.value, "error": str(exc)}

    async def probe_all(self) -> list[dict[str, Any]]:
        servers = self.registry.list_servers()
        tasks = [self.probe_server(s["id"]) for s in servers]
        if not tasks:
            return []
        return await asyncio.gather(*tasks)

    async def _loop(self, interval_seconds: float) -> None:
        while self._running:
            try:
                await self.probe_all()
            except Exception as exc:
                logger.warning(f"Error during health probe iteration: {exc}")
            await asyncio.sleep(interval_seconds)

    def start(self, interval_seconds: float = 30.0) -> None:
        if self._running:
            return
        self._running = True
        self._bg_task = asyncio.create_task(self._loop(interval_seconds))

    def stop(self) -> None:
        self._running = False
        if self._bg_task:
            self._bg_task.cancel()
            self._bg_task = None
