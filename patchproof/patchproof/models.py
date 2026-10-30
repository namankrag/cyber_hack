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
    """The gate's verdict for one finding + its candidate patch."""
    rule_id: str
    baseline_exploited: bool          # vuln confirmed on the unpatched app
    patched_exploited: bool           # exploit still works after patch?
    regression_before: list[CheckResult] = field(default_factory=list)
    regression_after: list[CheckResult] = field(default_factory=list)
    diff: str = ""
    patch_rationale: str = ""
    error: str | None = None

    @property
    def regression_after_passed(self) -> bool:
        return all(c.passed for c in self.regression_after)

    @property
    def accepted(self) -> bool:
        """A patch is accepted only if it PROVES both halves:
        the exploit is confirmed then blocked, AND functionality is preserved.
        """
        return (
            self.error is None
            and self.baseline_exploited          # it was really exploitable
            and not self.patched_exploited       # now it's blocked
            and self.regression_after_passed     # app still works
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
        return "FIXED & VERIFIED"
