"""W3C Trace Context & OpenTelemetry-over-MCP (_meta) propagation for MCP Gateway."""

from __future__ import annotations

import copy
import re
import secrets
import threading
from collections import deque
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

_TRACEPARENT_RE = re.compile(
    r"^(?P<version>[0-9a-f]{2})-(?P<trace_id>[0-9a-f]{32})-(?P<parent_id>[0-9a-f]{16})-(?P<flags>[0-9a-f]{2})$"
)
_ZERO_TRACE_ID = "0" * 32
_ZERO_SPAN_ID = "0" * 16


class TraceContext(BaseModel):
    """W3C Trace Context propagated across HTTP headers and MCP JSON-RPC _meta."""

    trace_id: str
    span_id: str
    parent_span_id: str | None = None
    trace_flags: str = "01"
    tracestate: str | None = None
    baggage: str | None = None
    source: str = "generated"

    @property
    def traceparent(self) -> str:
        return f"00-{self.trace_id}-{self.span_id}-{self.trace_flags}"


class GatewaySpan(BaseModel):
    """Lightweight OpenTelemetry-compatible span recorded by MCP Gateway."""

    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    trace_id: str
    span_id: str
    parent_span_id: str | None = None
    operation: str
    server_id: str
    tool_name: str | None = None
    principal: str = "anonymous"
    status: str = "ok"
    cached: bool = False
    latency_ms: float = 0.0
    source: str = "generated"
    tracestate: str | None = None
    baggage: str | None = None


def _parse_traceparent(raw: Any) -> tuple[str, str, str] | None:
    if not isinstance(raw, str):
        return None
    candidate = raw.strip().lower()
    match = _TRACEPARENT_RE.match(candidate)
    if not match:
        return None
    trace_id = match.group("trace_id")
    parent_id = match.group("parent_id")
    flags = match.group("flags")
    if trace_id == _ZERO_TRACE_ID or parent_id == _ZERO_SPAN_ID:
        return None
    if match.group("version") == "ff":
        return None
    return trace_id, parent_id, flags


def extract_trace_context(
    headers: Mapping[str, str],
    payload: dict[str, Any] | None = None,
) -> TraceContext:
    """
    Extract W3C Trace Context from MCP JSON-RPC params._meta (preferred) or HTTP headers.
    Always mints a fresh 64-bit gateway span_id while preserving trace_id & parent_span_id.
    """
    meta: dict[str, Any] = {}
    if isinstance(payload, dict):
        params = payload.get("params")
        if isinstance(params, dict) and isinstance(params.get("_meta"), dict):
            meta = params["_meta"]

    parsed_meta = _parse_traceparent(meta.get("traceparent"))
    parsed_hdr = _parse_traceparent(headers.get("traceparent"))

    if parsed_meta is not None:
        trace_id, parent_span_id, trace_flags = parsed_meta
        source = "mcp_meta"
    elif parsed_hdr is not None:
        trace_id, parent_span_id, trace_flags = parsed_hdr
        source = "http_header"
    else:
        trace_id = secrets.token_hex(16)
        parent_span_id = None
        trace_flags = "01"
        source = "generated"

    tracestate = meta.get("tracestate") if isinstance(meta.get("tracestate"), str) else headers.get("tracestate")
    baggage = meta.get("baggage") if isinstance(meta.get("baggage"), str) else headers.get("baggage")

    return TraceContext(
        trace_id=trace_id,
        span_id=secrets.token_hex(8),
        parent_span_id=parent_span_id,
        trace_flags=trace_flags,
        tracestate=tracestate.strip() if isinstance(tracestate, str) and tracestate.strip() else None,
        baggage=baggage.strip() if isinstance(baggage, str) and baggage.strip() else None,
        source=source,
    )


def inject_trace_into_payload(payload: dict[str, Any], ctx: TraceContext) -> dict[str, Any]:
    """Return a copy of an MCP JSON-RPC payload with W3C Trace Context in params._meta."""
    enriched = copy.deepcopy(payload)
    params = enriched.get("params")
    if not isinstance(params, dict):
        params = {}
        enriched["params"] = params
    meta = params.get("_meta")
    if not isinstance(meta, dict):
        meta = {}
        params["_meta"] = meta

    meta["traceparent"] = ctx.traceparent
    if ctx.tracestate:
        meta["tracestate"] = ctx.tracestate
    if ctx.baggage:
        meta["baggage"] = ctx.baggage
    return enriched


def inject_trace_into_headers(headers: dict[str, str], ctx: TraceContext) -> dict[str, str]:
    """Return a copy of HTTP headers enriched with W3C Trace Context fields."""
    out = dict(headers)
    out["traceparent"] = ctx.traceparent
    if ctx.tracestate:
        out["tracestate"] = ctx.tracestate
    if ctx.baggage:
        out["baggage"] = ctx.baggage
    return out


def attach_trace_meta_to_response(
    response_body: dict[str, Any],
    ctx: TraceContext,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Attach trace correlation metadata to JSON-RPC result._meta without mutating cached dicts."""
    enriched = copy.deepcopy(response_body)
    result = enriched.get("result")
    if isinstance(result, dict):
        meta = result.get("_meta")
        if not isinstance(meta, dict):
            meta = {}
        meta.update(
            {
                "traceparent": ctx.traceparent,
                "trace_id": ctx.trace_id,
                "span_id": ctx.span_id,
                "parent_span_id": ctx.parent_span_id,
            }
        )
        if extra:
            meta.update(extra)
        result["_meta"] = meta
    return enriched


class GatewayTelemetryCollector:
    """Thread-safe bounded ring buffer storing gateway execution spans."""

    def __init__(self, max_spans: int = 500) -> None:
        self._spans: deque[GatewaySpan] = deque(maxlen=max_spans)
        self._lock = threading.RLock()
        self._total_recorded = 0

    def record_span(self, span: GatewaySpan) -> None:
        with self._lock:
            self._spans.append(span)
            self._total_recorded += 1

    def list_spans(
        self,
        limit: int = 100,
        trace_id: str | None = None,
        server_id: str | None = None,
        status: str | None = None,
    ) -> list[dict[str, Any]]:
        with self._lock:
            items = list(self._spans)
        if trace_id:
            items = [s for s in items if s.trace_id == trace_id]
        if server_id:
            items = [s for s in items if s.server_id == server_id]
        if status:
            items = [s for s in items if s.status == status]
        if limit > 0:
            items = items[-limit:]
        return [s.model_dump() for s in reversed(items)]

    def stats(self) -> dict[str, Any]:
        with self._lock:
            buffered = len(self._spans)
            total = self._total_recorded
            error_spans = sum(1 for s in self._spans if s.status != "ok")
        return {
            "total_spans_recorded": total,
            "buffered_spans": buffered,
            "non_ok_buffered_spans": error_spans,
        }
