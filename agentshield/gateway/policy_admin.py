"""Safe policy changes: validate -> preview impact -> publish -> history/rollback.

Preview is side-effect free: the draft and the active policy each get a
throwaway engine (keyword detector only, like the frozen benchmark) and the
bench cases are evaluated directly, so nothing reaches the audit trail.

Publish is admin-gated at the HTTP layer and refuses when:
  * the active policy is pinned by digest (AGENTSHIELD_POLICY_SHA256): an
    operator froze the rules, so the console must not change them;
  * the file changed since the editor loaded it (optimistic concurrency);
  * the draft fails validation.
The previous file is kept under ``<policy dir>/.history/`` and every publish
or rollback appends a line to ``changes.jsonl`` there (who, when, old/new
SHA-256, impact summary). The file is replaced atomically, then the running
gateway hot-reloads (re-signed manifest, fresh engine) and cached isolated
runtimes are dropped so they rebuild from the new rules.
"""
from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import time
from pathlib import Path
from typing import Any

from ..detection.heuristic import HeuristicDetector
from ..engine_factory import AgentShield
from ..models import ToolCall, TrustLevel
from ..policy import PolicyEngine
from ..policy.loader import load_policy_text

MAX_POLICY_BYTES = 64 * 1024
_REPO_ROOT = Path(__file__).resolve().parents[2]
_CASES_PATH = _REPO_ROOT / "bench" / "cases.jsonl"
_VERSION_RE = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}\.yaml$")


class PolicyConflict(RuntimeError):
    """The change cannot be applied as asked (pinned policy, stale base, ...)."""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _policy_path(shield: AgentShield) -> Path:
    return Path(shield.config.policy_path)


def _history_dir(shield: AgentShield) -> Path:
    return _policy_path(shield).parent / ".history"


def _draft_text(body: Any) -> str:
    if not isinstance(body, dict) or not isinstance(body.get("yaml"), str):
        raise ValueError("send the draft policy as {\"yaml\": \"...\"}")
    text = body["yaml"]
    if not text.strip():
        raise ValueError("the draft policy is empty")
    if len(text.encode("utf-8")) > MAX_POLICY_BYTES:
        raise ValueError(f"the draft policy is larger than {MAX_POLICY_BYTES // 1024} KB")
    return text


def _validate(text: str):
    try:
        return load_policy_text(text, source="<draft>")
    except Exception as exc:  # yaml / pydantic / blank-name errors
        message = str(exc).strip().splitlines()
        raise ValueError(f"the draft policy is invalid: {' '.join(message[:6])[:600]}") from exc


def _cases() -> list[dict]:
    if not _CASES_PATH.is_file():
        return []
    with open(_CASES_PATH, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def _evaluate(engine: PolicyEngine, case: dict) -> str:
    call = ToolCall(tool_name=case["tool"], arguments=dict(case.get("arguments") or {}),
                    source=TrustLevel(case["source"]), context=case.get("context", ""))
    return engine.evaluate(call).decision.value


def _metrics(cases: list[dict], decisions: dict[str, str]) -> dict[str, float | None]:
    def rate(label: str, wanted: str) -> float | None:
        subset = [c for c in cases if c["label"] == label]
        if not subset:
            return None
        return round(sum(1 for c in subset if decisions[c["id"]] == wanted) / len(subset), 4)

    return {
        "attack_success": rate("malicious", "allow"),
        "attack_held": rate("malicious", "require_approval"),
        "attack_denied": rate("malicious", "deny"),
        "benign_denied": rate("benign", "deny"),
        "benign_held": rate("benign", "require_approval"),
        "approval_correctness": rate("approval", "require_approval"),
        "expected_match": round(sum(1 for c in cases if decisions[c["id"]] == c["expected_decision"])
                                / len(cases), 4) if cases else None,
    }


def preview(shield: AgentShield, body: Any) -> dict:
    """Validate a draft and show what it would change. Writes nothing."""
    text = _draft_text(body)
    active_bytes = _policy_path(shield).read_bytes()
    active_text = active_bytes.decode("utf-8")
    draft = _validate(text)
    cases = _cases()
    detectors = [HeuristicDetector()]
    current_engine = PolicyEngine(shield.policy, detectors)
    draft_engine = PolicyEngine(draft, detectors)
    before = {c["id"]: _evaluate(current_engine, c) for c in cases}
    after = {c["id"]: _evaluate(draft_engine, c) for c in cases}
    changed = [
        {"id": c["id"], "label": c["label"], "attack_type": c.get("attack_type"), "tool": c["tool"],
         "source": c["source"], "expected": c["expected_decision"],
         "before": before[c["id"]], "after": after[c["id"]]}
        for c in cases if before[c["id"]] != after[c["id"]]
    ]
    diff = list(difflib.unified_diff(active_text.splitlines(), text.splitlines(),
                                     "active", "draft", lineterm="", n=2))
    return {
        "valid": True,
        "active_sha256": _sha(active_bytes),
        "draft_sha256": _sha(text.encode("utf-8")),
        "identical": text == active_text,
        "diff": "\n".join(diff[:400]),
        "tools": sorted(draft.tools),
        "cases": len(cases),
        "metrics": {"active": _metrics(cases, before), "draft": _metrics(cases, after)},
        "changed": changed,
        "pinned": bool(os.getenv("AGENTSHIELD_POLICY_SHA256")),
    }


def _append_change(shield: AgentShield, entry: dict) -> None:
    history = _history_dir(shield)
    history.mkdir(parents=True, exist_ok=True)
    with open(history / "changes.jsonl", "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, sort_keys=True) + "\n")


def _apply(shield: AgentShield, new_text: str, base_sha: Any, action: str,
           note: str | None = None) -> dict:
    if os.getenv("AGENTSHIELD_POLICY_SHA256"):
        raise PolicyConflict("the active policy is pinned by AGENTSHIELD_POLICY_SHA256; "
                             "change it through review and redeploy, not from the console")
    path = _policy_path(shield)
    active_bytes = path.read_bytes()
    active_sha = _sha(active_bytes)
    if not isinstance(base_sha, str) or base_sha != active_sha:
        raise PolicyConflict("the policy changed since this editor loaded it; reload and review again")
    new_bytes = new_text.encode("utf-8")
    if new_bytes == active_bytes:
        raise ValueError("the draft is identical to the active policy")
    draft = _validate(new_text)
    impact = preview(shield, {"yaml": new_text})["metrics"]

    history = _history_dir(shield)
    history.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    saved = history / f"{stamp}-{active_sha[:12]}.yaml"
    saved.write_bytes(active_bytes)

    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_bytes(new_bytes)
    os.replace(tmp, path)
    try:
        shield.reload_policy(new_bytes, source=str(path))
    except Exception:
        os.replace(saved, path)  # put the previous rules back on disk
        saved.write_bytes(active_bytes)
        raise
    _drop_cached_runtimes()

    entry = {
        "at": time.time(), "action": action, "actor": "admin-session",
        "from_sha256": active_sha, "to_sha256": _sha(new_bytes),
        "previous_version": saved.name, "tools": sorted(draft.tools),
        "impact": impact, "note": (note or "")[:200],
    }
    _append_change(shield, entry)
    return {"published": True, **entry}


def _drop_cached_runtimes() -> None:
    from . import doclab, redteam
    doclab._RUNTIMES.clear()
    redteam._RUNTIMES.clear()


def publish(shield: AgentShield, body: Any) -> dict:
    text = _draft_text(body)
    return _apply(shield, text, body.get("base_sha256"), "publish", body.get("note"))


def rollback(shield: AgentShield, body: Any) -> dict:
    if not isinstance(body, dict):
        raise ValueError("send {\"version\": \"...\", \"base_sha256\": \"...\"}")
    version = body.get("version")
    if not isinstance(version, str) or not _VERSION_RE.match(version):
        raise ValueError("unknown policy version")
    file = _history_dir(shield) / version
    if not file.is_file():
        raise ValueError("unknown policy version")
    return _apply(shield, file.read_text(encoding="utf-8"), body.get("base_sha256"),
                  "rollback", f"restored {version}")


def history(shield: AgentShield, limit: int = 30) -> dict:
    changes_file = _history_dir(shield) / "changes.jsonl"
    changes: list[dict] = []
    if changes_file.is_file():
        for line in changes_file.read_text(encoding="utf-8").splitlines():
            try:
                changes.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    versions = sorted((p.name for p in _history_dir(shield).glob("*.yaml")
                       if _VERSION_RE.match(p.name)), reverse=True) if _history_dir(shield).is_dir() else []
    return {
        "active_sha256": _sha(_policy_path(shield).read_bytes()),
        "pinned": bool(os.getenv("AGENTSHIELD_POLICY_SHA256")),
        "changes": list(reversed(changes))[:limit],
        "versions": versions[:limit],
    }
