"""Orchestrates find -> prove -> patch -> prove-fixed for a target file."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .ai_patch import AIPatcher
from .checks import EXPLOIT_TEMPLATES
from .manifest import fixture_id_for_path
from .models import Finding, VerificationResult
from .patches import patch_for
from .sandbox import assert_bundled_fixture_target, run_fixture_jobs
from .scanner import scan
from .verifier import verify_patch, verify_source


@dataclass
class IssueReport:
    finding: Finding
    confirmed: bool                 # exploit proved the finding is real
    exploit_evidence: str
    verification: VerificationResult | None = None
    patch_source: str = "none"      # "curated" | "ai" | "ai-rejected→curated"

    @property
    def status(self) -> str:
        if not self.confirmed:
            return "NOT CONFIRMED (likely false positive)"
        return self.verification.verdict if self.verification else "UNPATCHED"


@dataclass
class PipelineResult:
    target: str
    engine: str = "ast"
    ai_enabled: bool = False
    issues: list[IssueReport] = field(default_factory=list)

    @property
    def confirmed(self) -> int:
        return sum(1 for i in self.issues if i.confirmed)

    @property
    def fixed(self) -> int:
        return sum(1 for i in self.issues
                   if i.verification and i.verification.accepted)

    @property
    def ai_fixes(self) -> int:
        return sum(1 for i in self.issues if i.patch_source == "ai")


def run_pipeline(target_file: str | Path, engine: str = "auto",
                 use_ai: bool = False, ai_provider: str | None = None) -> PipelineResult:
    target_file = Path(target_file)
    assert_bundled_fixture_target(target_file)
    original = target_file.read_text(encoding="utf-8")

    ai = AIPatcher(provider=ai_provider) if use_ai else None
    ai_on = bool(ai and ai.available())

    # 1) FIND
    findings = scan(target_file, engine=engine)
    resolved_engine = engine
    if engine == "auto":
        from . import semgrep_adapter
        resolved_engine = "both" if semgrep_adapter.available() else "ast"

    result = PipelineResult(target=str(target_file), engine=resolved_engine,
                            ai_enabled=ai_on)

    # Only findings with a registered CWE template can be proven; anything
    # else is reported with its scanner evidence and no patch attempt.
    provable = [f for f in findings if f.cwe in EXPLOIT_TEMPLATES]
    fixture = fixture_id_for_path(target_file) or "vulnbank"
    jobs = [
        {"key": f"finding-{index}", "source": original,
         "rule_id": finding.rule_id, "regressions": False,
         "fixture": fixture, "finding": finding.to_dict()}
        for index, finding in enumerate(provable)
    ]
    try:
        proofs = run_fixture_jobs(jobs)
    except (RuntimeError, TimeoutError) as exc:
        # Fail closed: a timed-out or failed sandbox proof cannot confirm a
        # finding or authorize a patch.
        proofs = {}
        sandbox_error = f"bounded fixture proof failed: {type(exc).__name__}: {exc}"
    else:
        sandbox_error = None

    # Job keys are indexed over the provable findings, so walk them in the
    # same order; findings without a template are reported unconfirmed.
    provable_index = {id(f): index for index, f in enumerate(provable)}
    for finding in findings:
        # 2) PROVE the finding is real with an executable exploit.
        if id(finding) in provable_index:
            proof = proofs.get(f"finding-{provable_index[id(finding)]}")
        else:
            proof = None
        ev = proof["exploit"] if proof else None
        confirmed = bool(ev and ev.exploited)
        issue = IssueReport(
            finding=finding, confirmed=confirmed,
            exploit_evidence=(ev.evidence if ev else
                              sandbox_error or "no exploit available"),
        )

        if confirmed:
            issue.verification, issue.patch_source = _best_patch(
                target_file, finding, ai if ai_on else None)

        result.issues.append(issue)

    return result


def _best_patch(target_file, finding, ai):
    """Try an AI patch first (if enabled); accept it only if it passes the gate.
    Otherwise (or on rejection) fall back to the curated patch.
    """
    rule_id = finding.rule_id

    patch = patch_for(target_file, rule_id)
    if ai is not None:
        candidate = ai.propose(target_file, rule_id, finding.line)
        if candidate is not None:
            v = verify_source(target_file, candidate, rule_id,
                              rationale="AI-generated patch, verified by the gate")
            if v.accepted:
                return v, "ai"
            # AI produced something, but it failed the gate -> fall back.
            if patch is not None:
                return verify_patch(target_file, patch), "ai-rejected→curated"
            return v, "ai (rejected)"

    if patch is not None:
        return verify_patch(target_file, patch), "curated"
    return None, "none"
