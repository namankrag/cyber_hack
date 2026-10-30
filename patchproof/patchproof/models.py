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


#: A patch touching more changed lines than this is flagged "not minimal".
#: The largest curated PatchProof patch touches 13 lines; 30 leaves ample
#: headroom for legitimate fixes while catching pasted-in rewrites.
MINIMAL_PATCH_MAX_LINES = 30


# --------------------------------------------------------------------------
# Item-5 CVSS v3.1: pure functions, no dependencies.
# --------------------------------------------------------------------------

_CVSS_NUMBERS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
    "PRC": {"N": 0.85, "L": 0.68, "H": 0.5},  # PR weights when Scope = Changed
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"N": 0.0, "L": 0.22, "H": 0.56},
}

_CVSS_NAMES = {
    "AV": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
    "AC": {"L": "Low", "H": "High"},
    "PR": {"N": "None", "L": "Low", "H": "High"},
    "UI": {"N": "None", "R": "Required"},
    "S": {"U": "Unchanged", "C": "Changed"},
    "C": {"N": "None", "L": "Low", "H": "High"},
    "I": {"N": "None", "L": "Low", "H": "High"},
    "A": {"N": "None", "L": "Low", "H": "High"},
}


def _roundup(value: float) -> float:
    """CVSS v3.1 Roundup: smallest 1-decimal number >= the input."""
    scaled = round(value * 100000)
    if scaled % 10000 == 0:
        return scaled / 100000
    return (scaled // 10000 + 1) / 10


def cvss31_score(vector: str) -> float:
    """Base score (0.0–10.0) for a ``CVSS:3.1/...`` vector string.

    Pure function implementing the FIRST v3.1 specification equations,
    including the Scope-Changed impact form. Raises ValueError on malformed
    input (fail-closed: no score is better than a wrong score).
    """
    parts = vector.split("/")
    if not parts or parts[0] != "CVSS:3.1":
        raise ValueError(f"not a CVSS v3.1 vector: {vector!r}")
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        if ":" not in part:
            raise ValueError(f"malformed vector segment {part!r}")
        key, val = part.split(":", 1)
        metrics[key] = val
    try:
        av = _CVSS_NUMBERS["AV"][metrics["AV"]]
        ac = _CVSS_NUMBERS["AC"][metrics["AC"]]
        scope_changed = metrics["S"] == "C"
        pr_table = _CVSS_NUMBERS["PRC" if scope_changed else "PR"]
        pr = pr_table[metrics["PR"]]
        ui = _CVSS_NUMBERS["UI"][metrics["UI"]]
        c = _CVSS_NUMBERS["CIA"][metrics["C"]]
        i = _CVSS_NUMBERS["CIA"][metrics["I"]]
        a = _CVSS_NUMBERS["CIA"][metrics["A"]]
    except KeyError as exc:
        raise ValueError(f"unknown CVSS metric value: {exc}") from exc
    if metrics["S"] not in ("U", "C"):
        raise ValueError(f"unknown Scope value: {metrics['S']!r}")

    isc = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a)
    if scope_changed:
        impact = 7.52 * (isc - 0.029) - 3.25 * pow(isc - 0.02, 15)
    else:
        impact = 6.42 * isc
    exploit = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    if scope_changed:
        return _roundup(min(1.08 * (impact + exploit), 10.0))
    return _roundup(min(impact + exploit, 10.0))


def _cvss_severity(score: float) -> str:
    if score == 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


@dataclass
class CvssAssessment:
    """CVSS v3.1 vector + base score for one finding, with per-metric notes."""
    vector: str
    base_score: float
    severity: str
    metrics: dict[str, str] = field(default_factory=dict)


def _base_rule_id(rule_id: str) -> str:
    return rule_id[:-len("-decoy")] if rule_id.endswith("-decoy") else rule_id


#: Per-CWE metric assignment: (vector, {metric: one-line justification}).
_CVSS_BY_RULE: dict[str, tuple[str, dict[str, str]]] = {
    "sqli": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", {
        "AV:N": "login is reachable over the network",
        "AC:L": "a single quote breaks out of the query",
        "PR:N": "exploited pre-auth, no account needed",
        "UI:N": "no victim interaction required",
        "S:U": "impact stays inside the fixture app",
        "C:H": "admin row (and its data) is disclosed",
        "I:H": "attacker authenticates as admin",
        "A:N": "no denial of service demonstrated",
    }),
    "cmdi": ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", {
        "AV:N": "ping endpoint is reachable over the network",
        "AC:L": "a semicolon starts a second command",
        "PR:L": "needs any low-priv Bearer id",
        "UI:N": "no victim interaction required",
        "S:U": "impact stays inside the fixture app",
        "C:H": "arbitrary commands read host data",
        "I:H": "arbitrary commands change host state",
        "A:H": "arbitrary commands can halt the host",
    }),
    "pathtrav": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", {
        "AV:N": "files endpoint is reachable over the network",
        "AC:L": "plain ../ escapes the docs directory",
        "PR:N": "no authentication required",
        "UI:N": "no victim interaction required",
        "S:U": "impact stays inside the fixture app",
        "C:H": "sibling secret file is disclosed",
        "I:N": "read-only access demonstrated",
        "A:N": "no denial of service demonstrated",
    }),
    "idor": ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", {
        "AV:N": "account route is reachable over the network",
        "AC:L": "guessing neighbouring ids is trivial",
        "PR:L": "needs any low-priv Bearer id",
        "UI:N": "no victim interaction required",
        "S:U": "impact stays inside the fixture app",
        "C:H": "another user's balance is disclosed",
        "I:N": "read-only access demonstrated",
        "A:N": "no denial of service demonstrated",
    }),
    "xss": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", {
        "AV:N": "greet page is reachable over the network",
        "AC:L": "a bare <script> reflects unescaped",
        "PR:N": "no authentication required",
        "UI:R": "a victim must open the crafted link",
        "S:C": "script runs in the victim's browser",
        "C:L": "session data of one user at risk",
        "I:L": "actions as one user at risk",
        "A:N": "no denial of service demonstrated",
    }),
    "pickle": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", {
        "AV:N": "import endpoint is reachable over the network",
        "AC:L": "any base64 blob reaches pickle.loads",
        "PR:N": "no authentication required",
        "UI:N": "no victim interaction required",
        "S:U": "impact stays inside the fixture app",
        "C:H": "deserialization can read host data",
        "I:H": "deserialization can change host state",
        "A:H": "deserialization can halt the host",
    }),
    "secret": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", {
        "AV:N": "report endpoint is reachable over the network",
        "AC:L": "the key sits in readable source",
        "PR:N": "no prior access required",
        "UI:N": "no victim interaction required",
        "S:U": "impact stays inside the fixture app",
        "C:H": "the admin report is disclosed",
        "I:N": "read-only access demonstrated",
        "A:N": "no denial of service demonstrated",
    }),
}


def cvss_for_finding(finding) -> CvssAssessment:
    """CVSS v3.1 assessment for one finding (decoys share the base rule's)."""
    rule_id = getattr(finding, "rule_id", "")
    base = _base_rule_id(rule_id)
    try:
        vector, notes = _CVSS_BY_RULE[base]
    except KeyError:
        raise KeyError(
            f"no CVSS mapping registered for rule {rule_id!r}") from None
    score = cvss31_score(vector)
    return CvssAssessment(vector=vector, base_score=score,
                          severity=_cvss_severity(score),
                          metrics=dict(notes))


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
    # Item-4 per-function line coverage of the patched copy, measured while
    # the patched exploit + regression runs execute (fraction per function
    # the patch touches; {} when coverage could not be measured).
    coverage: dict[str, float] = field(default_factory=dict)
    # Item-5 diff size + minimality: added/removed lines, touched functions,
    # and whether the patch exceeds MINIMAL_PATCH_MAX_LINES (advisory flag,
    # never a gate rejection).
    lines_added: int = 0
    lines_removed: int = 0
    functions_touched: list[str] = field(default_factory=list)
    is_minimal: bool = True
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
