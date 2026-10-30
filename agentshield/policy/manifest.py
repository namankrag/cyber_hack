"""Signed tool manifest — rug-pull / tool-poisoning tripwire.

At startup AgentShield HMAC-signs every governed tool's definition with the
harness secret (`AGENTSHIELD_HARNESS_SECRET`) into a manifest. Every
in-process check re-verifies the tool's *current* policy entry against that
signature, and every MCP call re-verifies the tool's *live* description and
input schema. If a description or schema changed after registration —
a simulated rug-pull ("update the tool, keep the name") or tool-poisoning
("the docs now tell the agent to exfiltrate") — verification fails and the
call is DENIED with an inspectable `tool_manifest_mismatch` reason.

Trust root: the same harness secret as provenance tokens. With no secret
configured (insecure dev mode) nothing can be authenticated, so the manifest
is built unsigned and verification is skipped — but explicitly *flagged* via
`manifest_enforced == False` (surfaced in /v1/evidence), mirroring the
provenance dev-mode philosophy: never silently permissive.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass, field

from .models import _norm_tool_key  # policy package sibling

MANIFEST_RULE = "tool_manifest_mismatch"


def _secret() -> bytes | None:
    s = os.getenv("AGENTSHIELD_HARNESS_SECRET")
    return s.encode() if s else None


def _canonical(obj: object) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      default=str)


def _sign(payload: str, key: bytes) -> str:
    return hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()


@dataclass
class _ToolRecord:
    """What the manifest knows about one governed tool at startup."""

    name: str
    description: str = ""
    schema: dict = field(default_factory=dict)
    policy: dict = field(default_factory=dict)
    policy_sig: str | None = None
    tool_sig: str | None = None


class ToolManifest:
    """Startup signatures for governed tools; verifies live definitions.

    Two fingerprints per tool, because the two enforcement doors observe
    different things: the engine door observes the *policy entry* (rules),
    the MCP door observes the *live tool* (description + input schema).
    A record only carries the fingerprints its builder supplied; `verify_*`
    on an uncovered field passes with a "not covered" reason.
    """

    def __init__(self, records: dict[str, _ToolRecord],
                 signed: bool) -> None:
        self._records = records
        self.signed = signed

    @property
    def enforced(self) -> bool:
        """False in insecure dev mode (no secret): verification is skipped."""
        return self.signed

    @classmethod
    def _build(cls, items: dict[str, dict],
               secret: bytes | None) -> "ToolManifest":
        records: dict[str, _ToolRecord] = {}
        for name, item in items.items():
            key = _norm_tool_key(name)
            if not key:
                continue
            rec = _ToolRecord(
                name=name,
                description=item.get("description") or "",
                schema=item.get("schema") or {},
                policy=item.get("policy") or {},
            )
            if secret is not None:
                if rec.policy:
                    rec.policy_sig = _sign(
                        _canonical({"v": 1, "tool": key,
                                    "policy": rec.policy}), secret)
                if rec.description or rec.schema:
                    rec.tool_sig = _sign(
                        _canonical({"v": 1, "tool": key,
                                    "description": rec.description,
                                    "schema": rec.schema}), secret)
            records[key] = rec
        return cls(records, signed=secret is not None)

    @classmethod
    def from_policy(cls, policy, secret: bytes | None = None) -> "ToolManifest":
        """Sign every governed tool's policy entry (engine-door tripwire)."""
        items = {name: {"policy": tool.model_dump(mode="json")}
                 for name, tool in policy.tools.items()}
        return cls._build(items, secret if secret is not None else _secret())

    @classmethod
    def from_tools(cls, tools: dict[str, dict],
                   secret: bytes | None = None) -> "ToolManifest":
        """Sign live tool identities: {name: {"description":..., "schema":...}}."""
        return cls._build(tools, secret if secret is not None else _secret())

    def verify_policy(self, name: str, policy: dict) -> tuple[bool, str]:
        """Re-verify a tool's current policy entry against the startup signature."""
        if not isinstance(name, str):
            return True, "manifest: tool name not a string (handled by policy)"
        rec = self._records.get(_norm_tool_key(name))
        if rec is None:
            return True, "manifest: tool not governed (unknown-tool rule applies)"
        if not self.signed:
            return True, ("manifest unsigned (insecure dev mode, no harness "
                           "secret): policy verification skipped, flagged in "
                           "/v1/evidence")
        if rec.policy_sig is None:
            return True, "manifest: no policy fingerprint for this tool"
        expected = _sign(_canonical({"v": 1, "tool": _norm_tool_key(name),
                                     "policy": policy or {}}),
                         _require_secret())
        if hmac.compare_digest(expected, rec.policy_sig):
            return True, "manifest: policy entry matches startup signature"
        return False, (f"manifest: policy entry for '{name}' changed after "
                       "startup (possible rug-pull of the governed tool "
                       "definition); refusing")

    def verify_tool(self, name: str, description: str | None,
                    schema: dict | None) -> tuple[bool, str]:
        """Re-verify a live tool's description+schema (MCP-door tripwire)."""
        if not isinstance(name, str):
            return True, "manifest: tool name not a string (handled upstream)"
        rec = self._records.get(_norm_tool_key(name))
        if rec is None:
            return True, "manifest: tool not governed (unknown-tool rule applies)"
        if not self.signed:
            return True, ("manifest unsigned (insecure dev mode, no harness "
                           "secret): tool verification skipped, flagged in "
                           "/v1/evidence")
        if rec.tool_sig is None:
            return True, "manifest: no tool fingerprint for this tool"
        expected = _sign(_canonical({"v": 1, "tool": _norm_tool_key(name),
                                     "description": description or "",
                                     "schema": schema or {}}),
                         _require_secret())
        if hmac.compare_digest(expected, rec.tool_sig):
            return True, "manifest: tool identity matches startup signature"
        return False, (f"manifest: description or schema for '{name}' changed "
                       "after registration (possible rug-pull/tool-poisoning); "
                       "refusing")


def _require_secret() -> bytes:
    key = _secret()
    if key is None:  # pragma: no cover - callers check signed first
        raise RuntimeError("manifest verification needs AGENTSHIELD_HARNESS_SECRET")
    return key
