"""Shared data models for the PatchProof pipeline."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class Finding:
    """One weakness located by the scanner (the 'find' step)."""
    rule_id: str                 # e.g. "sqli", links finding -> exploit/patch
    cwe: str                     # e.g. "CWE-89"
    title: str
    severity: Severity
    severity_rationale: str
    file: str
    line: int
    snippet: str                 # the offending source line
    evidence: str = ""           # why the scanner flagged it
    # Request shape, filled by the scanner so exploits and regression probes
    # can be written as per-CWE templates instead of hardcoding endpoints.
    route: str = ""              # e.g. "/accounts/<int:account_id>"
    method: str = ""             # e.g. "GET"
    param: str = ""              # tainted request parameter, e.g. "username"
    sink: str = ""               # dangerous operation, e.g. "cursor.execute"
    # Item-3 variant payload override: when set, the exploit template attacks
    # with this payload instead of the canned probe (lets the sandboxed gate
    # replay a whole payload corpus through the same jobs; "" = original).
    variant: str = ""

    def to_dict(self) -> dict:
        """JSON-safe snapshot, carried on sandbox jobs (patched runs included)."""
        return {
            "rule_id": self.rule_id,
            "cwe": self.cwe,
            "title": self.title,
            "severity": self.severity.value,
            "severity_rationale": self.severity_rationale,
            "file": self.file,
            "line": self.line,
            "snippet": self.snippet,
            "evidence": self.evidence,
            "route": self.route,
            "method": self.method,
            "param": self.param,
            "sink": self.sink,
            "variant": self.variant,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        """Rebuild a Finding from a to_dict() snapshot."""
        return cls(
            rule_id=data.get("rule_id", ""),
            cwe=data.get("cwe", ""),
            title=data.get("title", ""),
            severity=Severity(data.get("severity", "medium")),
            severity_rationale=data.get("severity_rationale", ""),
            file=data.get("file", ""),
            line=int(data.get("line", 0)),
            snippet=data.get("snippet", ""),
            evidence=data.get("evidence", ""),
            route=data.get("route", ""),
            method=data.get("method", ""),
            param=data.get("param", ""),
            sink=data.get("sink", ""),
            variant=data.get("variant", ""),
        )


@dataclass
class ExploitResult:
    """Outcome of running an exploit against a running app."""
    exploited: bool              # True = the attack succeeded
    evidence: str                # request/response proof


@dataclass
class CheckResult:
    """One functional (regression) assertion."""
    name: str
    passed: bool
    detail: str = ""


@dataclass
class VerificationResult:
    """The gate's verdict for one finding + its candidate fix."""
    rule_id: str
    baseline_exploited: bool          # vuln confirmed on the unpatched app
    patched_exploited: bool           # exploit still works after patch?
    regression_before: list[CheckResult] = field(default_factory=list)
    regression_after: list[CheckResult] = field(default_factory=list)
    diff: str = ""
    patch_rationale: str = ""
    error: str | None = None
    verification_time_ms: float = 0.0
    # Item-3 variant gate: every corpus payload replayed against the patched
    # copy must be blocked. The first payload that still exploits names the
    # bypass (None when all blocked).
    bypass_payload: str | None = None
    variants_total: int = 0
    variants_blocked: int = 0

    @property
    def regression_after_passed(self) -> bool:
        return all(c.passed for c in self.regression_after)

    @property
    def accepted(self) -> bool:
        """A patch is accepted only if it PROVES both halves:
        the exploit is confirmed then blocked, AND functionality is preserved.
        Since Item 3, every corpus variant must be blocked too: a surviving
        variant (bypass_payload set) rejects the patch even when the canned
        probe is stopped and the app still works.
        """
        return (
            self.error is None
            and self.baseline_exploited          # it was really exploitable
            and not self.patched_exploited       # now it's blocked
            and self.regression_after_passed     # app still works
            and self.bypass_payload is None      # no variant got through
        )

    @property
    def verdict(self) -> str:
        if self.error:
            return "ERROR"
        if not self.baseline_exploited:
            return "NOT CONFIRMED"               # scanner noise / false positive
        if self.patched_exploited:
            return "PATCH INEFFECTIVE"
        if not self.regression_after_passed:
            return "PATCH BREAKS APP"            # rejected: regression failed
        if self.bypass_payload is not None:
            return "PATCH BYPASSABLE"            # rejected: a variant got through
        return "FIXED & VERIFIED"
