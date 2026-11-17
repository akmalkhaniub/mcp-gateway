"""Principal Access Boundary, Tool Governance, HITL Approval Tokens, and Audit Trail for MCP Gateway."""

from __future__ import annotations

import base64
import fnmatch
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from collections import deque
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class PolicyEffect(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class EnforcementMode(StrEnum):
    ENFORCED = "enforced"
    DRY_RUN = "dry_run"


class ToolAccessPolicy(BaseModel):
    """Unified Access Policy binding an Agent Identity principal pattern to MCP tools."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    id: str
    name: str
    principal_pattern: str = "*"
    server_pattern: str = "*"
    tool_pattern: str = "*"
    effect: PolicyEffect = PolicyEffect.ALLOW
    mode: EnforcementMode = EnforcementMode.ENFORCED
    require_approval: bool = False
    priority: int = 100
    description: str = ""


class PolicyDecision(BaseModel):
    allowed: bool
    effect: PolicyEffect
    mode: EnforcementMode
    matched_policy_id: str | None = None
    dry_run_would_deny: bool = False
    require_approval: bool = False
    reason: str = "Allowed by default gateway policy."


class ApprovalTokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    principal: str
    server_id: str = "*"
    tool_name: str
    ttl_seconds: int = Field(default=300, ge=1, le=86400)


class AuditLogEntry(BaseModel):
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    principal: str
    server_id: str
    tool_name: str
    decision: str
    policy_id: str | None = None
    mode: str = EnforcementMode.ENFORCED.value
    cached: bool = False
    latency_ms: float = 0.0
    reason: str = ""


class McpGovernanceEngine:
    """Evaluates Principal Access Boundaries, HITL approval tokens, and records tool audit logs."""

    def __init__(self, approval_secret: str | None = None, max_audit_entries: int = 500) -> None:
        secret = approval_secret or os.environ.get("MCP_GATEWAY_APPROVAL_SECRET") or secrets.token_hex(32)
        self._secret = secret.encode("utf-8")
        self._policies: dict[str, ToolAccessPolicy] = {}
        self._audit_logs: deque[AuditLogEntry] = deque(maxlen=max_audit_entries)
        self._lock = threading.RLock()

    def upsert_policy(self, policy: ToolAccessPolicy) -> ToolAccessPolicy:
        with self._lock:
            self._policies[policy.id] = policy
            return policy

    def remove_policy(self, policy_id: str) -> bool:
        with self._lock:
            return self._policies.pop(policy_id, None) is not None

    def list_policies(self) -> list[ToolAccessPolicy]:
        with self._lock:
            return sorted(
                self._policies.values(),
                key=lambda p: (-p.priority, 0 if p.effect == PolicyEffect.DENY else 1, p.id),
            )

    def issue_approval_token(
        self,
        principal: str,
        server_id: str,
        tool_name: str,
        ttl_seconds: int = 300,
    ) -> tuple[str, int]:
        """Issue an HMAC-SHA256 signed HITL approval token scoped to principal, server, and tool."""
        exp = int(time.time()) + ttl_seconds
        claims = {
            "sub": principal,
            "srv": server_id,
            "tool": tool_name,
            "exp": exp,
            "jti": secrets.token_hex(8),
        }
        payload_bytes = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode("utf-8")
        payload_b64 = base64.urlsafe_b64encode(payload_bytes).decode("ascii").rstrip("=")
        sig = hmac.new(self._secret, payload_b64.encode("ascii"), hashlib.sha256).hexdigest()
        return f"{payload_b64}.{sig}", exp

    def verify_approval_token(
        self,
        token: str | None,
        principal: str,
        server_id: str,
        tool_name: str,
    ) -> tuple[bool, str]:
        """Verify HMAC signature, expiration, and scope binding for an HITL approval token."""
        if not token or "." not in token:
            return False, "Missing or malformed X-Approval-Token."

        payload_b64, provided_sig = token.rsplit(".", 1)
        expected_sig = hmac.new(self._secret, payload_b64.encode("ascii"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(provided_sig, expected_sig):
            return False, "Invalid X-Approval-Token signature."

        try:
            padded = payload_b64 + "=" * (-len(payload_b64) % 4)
            claims = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
        except Exception:
            return False, "Corrupt X-Approval-Token payload."

        if int(claims.get("exp", 0)) < int(time.time()):
            return False, "X-Approval-Token has expired."

        if claims.get("sub") != principal:
            return False, "X-Approval-Token principal mismatch."

        srv_claim = claims.get("srv", "*")
        if srv_claim != "*" and srv_claim != server_id:
            return False, "X-Approval-Token server mismatch."

        if claims.get("tool") != tool_name:
            return False, "X-Approval-Token tool mismatch."

        return True, "Valid HITL approval token."

    def evaluate(
        self,
        principal: str,
        server_id: str,
        tool_name: str,
        approval_token: str | None = None,
    ) -> PolicyDecision:
        """Evaluate matching policies in priority order (fail-closed on ties)."""
        policies = self.list_policies()
        for policy in policies:
            if not (
                fnmatch.fnmatchcase(principal, policy.principal_pattern)
                and fnmatch.fnmatchcase(server_id, policy.server_pattern)
                and fnmatch.fnmatchcase(tool_name, policy.tool_pattern)
            ):
                continue

            if policy.effect == PolicyEffect.DENY:
                if policy.mode == EnforcementMode.DRY_RUN:
                    return PolicyDecision(
                        allowed=True,
                        effect=PolicyEffect.DENY,
                        mode=EnforcementMode.DRY_RUN,
                        matched_policy_id=policy.id,
                        dry_run_would_deny=True,
                        reason=f"DRY_RUN audit: policy '{policy.id}' would deny '{tool_name}' for '{principal}'.",
                    )
                return PolicyDecision(
                    allowed=False,
                    effect=PolicyEffect.DENY,
                    mode=EnforcementMode.ENFORCED,
                    matched_policy_id=policy.id,
                    reason=f"Denied by policy '{policy.id}' ({policy.name}).",
                )

            if policy.require_approval:
                ok, token_msg = self.verify_approval_token(approval_token, principal, server_id, tool_name)
                if ok:
                    return PolicyDecision(
                        allowed=True,
                        effect=PolicyEffect.ALLOW,
                        mode=policy.mode,
                        matched_policy_id=policy.id,
                        require_approval=True,
                        reason=f"Allowed by policy '{policy.id}' with verified HITL approval token.",
                    )
                if policy.mode == EnforcementMode.DRY_RUN:
                    return PolicyDecision(
                        allowed=True,
                        effect=PolicyEffect.ALLOW,
                        mode=EnforcementMode.DRY_RUN,
                        matched_policy_id=policy.id,
                        dry_run_would_deny=True,
                        require_approval=True,
                        reason=f"DRY_RUN audit: policy '{policy.id}' requires HITL approval ({token_msg}).",
                    )
                return PolicyDecision(
                    allowed=False,
                    effect=PolicyEffect.DENY,
                    mode=EnforcementMode.ENFORCED,
                    matched_policy_id=policy.id,
                    require_approval=True,
                    reason=f"HITL approval required by policy '{policy.id}': {token_msg}",
                )

            return PolicyDecision(
                allowed=True,
                effect=PolicyEffect.ALLOW,
                mode=policy.mode,
                matched_policy_id=policy.id,
                reason=f"Allowed by policy '{policy.id}' ({policy.name}).",
            )

        return PolicyDecision(
            allowed=True,
            effect=PolicyEffect.ALLOW,
            mode=EnforcementMode.ENFORCED,
            matched_policy_id=None,
            reason="Allowed by default gateway policy.",
        )

    def record_audit(self, entry: AuditLogEntry) -> None:
        with self._lock:
            self._audit_logs.append(entry)

    def list_audit_logs(
        self,
        limit: int = 100,
        principal: str | None = None,
        decision: str | None = None,
    ) -> list[dict[str, Any]]:
        with self._lock:
            items = list(self._audit_logs)
        if principal:
            items = [e for e in items if e.principal == principal]
        if decision:
            items = [e for e in items if e.decision == decision]
        if limit > 0:
            items = items[-limit:]
        return [e.model_dump() for e in reversed(items)]

    def audit_count(self) -> int:
        with self._lock:
            return len(self._audit_logs)
