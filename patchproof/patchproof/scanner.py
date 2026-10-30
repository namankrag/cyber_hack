"""SAST scanner — the 'find' step.

A lightweight but real static analyzer built on Python's `ast`. It locates the
three weakness classes by their code shape and reports each with an exact
file:line, CWE, severity, and the offending source snippet.

Design choice (mirrors the PS-02 problem): scanners are noisy. The scanner here
is intentionally conservative about *taint* — it flags a dangerous shape, but
PatchProof never trusts a finding on the scanner's word alone. Every finding is
independently confirmed by an executable exploit before it is acted on (see the
verifier). So a scanner false positive simply fails to confirm and is dropped.

An optional Semgrep adapter is included for parity with real-world tooling; the
AST scanner is the default so the tool is self-contained.
"""
from __future__ import annotations

import ast
from pathlib import Path

from .models import Finding, Severity

_SEVERITY = {
    "sqli": (Severity.CRITICAL, "Pre-auth data exposure / full auth bypass; "
                                 "trivially exploitable, high impact."),
    "cmdi": (Severity.CRITICAL, "Arbitrary command execution on the host; "
                                 "trivially exploitable, highest impact."),
    "pathtrav": (Severity.HIGH, "Reads arbitrary files outside the intended "
                                "directory; easy to exploit."),
    "idor": (Severity.HIGH, "Authenticated user can access other users' data; "
                            "easy to exploit, confidentiality impact."),
    "xss": (Severity.MEDIUM, "Reflected script executes in a victim's browser; "
                             "session/credential theft."),
}
_CWE = {"sqli": "CWE-89", "cmdi": "CWE-78", "idor": "CWE-639",
        "pathtrav": "CWE-22", "xss": "CWE-79"}
_TITLE = {
    "sqli": "SQL injection: user input in SQL string",
    "cmdi": "OS command injection: user input in shell command",
    "idor": "Broken access control: object returned without ownership check",
    "pathtrav": "Path traversal: user input in a filesystem path",
    "xss": "Reflected XSS: user input returned in HTML unescaped",
}


class _Visitor(ast.NodeVisitor):
    """Per-function pass with a tiny intra-procedural taint set.

    A variable assigned a dynamic string (f-string / concat / %-format) is
    marked tainted; a `.execute(var)` or shell call on a tainted var — or on a
    dynamic string directly — is flagged. This catches the common real pattern
    where the query is built on one line and executed on the next.
    """

    def __init__(self, source_lines: list[str]) -> None:
        self.lines = source_lines
        self.hits: list[tuple[str, int, str]] = []  # (rule_id, line, snippet)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        tainted: set[str] = set()
        for n in ast.walk(node):
            if isinstance(n, ast.Assign) and _is_dynamic_string(n.value):
                for t in n.targets:
                    if isinstance(t, ast.Name):
                        tainted.add(t.id)
        for n in ast.walk(node):
            if isinstance(n, ast.Call):
                self._check_sqli(n, tainted)
                self._check_cmdi(n, tainted)
                self._check_pathtrav(n, tainted)
            if isinstance(n, ast.Return) and n.value is not None:
                self._check_xss(n)
        self.generic_visit(node)

    def _tainted_arg(self, arg: ast.AST, tainted: set[str]) -> bool:
        if _is_dynamic_string(arg):
            return True
        return isinstance(arg, ast.Name) and arg.id in tainted

    def _check_sqli(self, node: ast.Call, tainted: set[str]) -> None:
        if not (isinstance(node.func, ast.Attribute) and node.func.attr == "execute"):
            return
        if node.args and self._tainted_arg(node.args[0], tainted):
            self.hits.append(("sqli", node.lineno, self._src(node.lineno)))

    def _check_cmdi(self, node: ast.Call, tainted: set[str]) -> None:
        name = _dotted(node.func)
        if name in {"os.system", "os.popen", "subprocess.call",
                    "subprocess.run", "subprocess.Popen"}:
            if node.args and self._tainted_arg(node.args[0], tainted):
                self.hits.append(("cmdi", node.lineno, self._src(node.lineno)))

    def _check_pathtrav(self, node: ast.Call, tainted: set[str]) -> None:
        # open(<dynamic path>) with user-influenced input.
        if isinstance(node.func, ast.Name) and node.func.id == "open":
            if node.args and self._tainted_arg(node.args[0], tainted):
                self.hits.append(("pathtrav", node.lineno, self._src(node.lineno)))

    def _check_xss(self, node: ast.Return) -> None:
        # A handler returning a dynamic string that looks like HTML (contains a
        # tag) with no escaping is a reflected-XSS candidate.
        if _is_dynamic_string(node.value):
            line = self._src(node.lineno)
            if "<" in line and "escape" not in line:
                self.hits.append(("xss", node.lineno, line))

    def _src(self, lineno: int) -> str:
        return self.lines[lineno - 1].strip() if 0 < lineno <= len(self.lines) else ""


def _is_dynamic_string(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):          # f"...{x}..."
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True                               # "..." + x  or  "..." % x
    return False


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return f"{node.value.id}.{node.attr}"
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _scan_idor(tree: ast.AST, lines: list[str]) -> list[tuple[str, int, str]]:
    """Heuristic authz check: find the /accounts/<id> handler and flag it if its
    body never compares the record's owner to the current user.

    (Real authz detection is hard for generic SAST; this is a targeted,
    explainable heuristic. As with every finding, it only matters once the
    exploit confirms it.)
    """
    hits = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        is_accounts = any(
            isinstance(d, ast.Call)
            and "/accounts/" in "".join(
                a.value for a in d.args if isinstance(a, ast.Constant)
                and isinstance(a.value, str))
            for d in node.decorator_list
        )
        if not is_accounts:
            continue
        body_src = "\n".join(lines[node.lineno - 1:node.end_lineno])
        has_owner_check = ("owner_id" in body_src and
                           ("user" in body_src) and
                           ("!=" in body_src or "==" in body_src or
                            "authorize" in body_src))
        if not has_owner_check:
            hits.append(("idor", node.lineno, lines[node.lineno - 1].strip()))
    return hits


def scan(path: str | Path, engine: str = "auto") -> list[Finding]:
    """Scan with the chosen engine.

      "ast"     — built-in analyzer only (always available, self-contained).
      "semgrep" — Semgrep only (raises if unavailable).
      "both"    — union of both, de-duplicated by (rule_id, line).
      "auto"    — "both" if Semgrep is available, else "ast".
    """
    from . import semgrep_adapter

    path = Path(path)
    if engine == "auto":
        engine = "both" if semgrep_adapter.available() else "ast"

    findings: list[Finding] = []
    if engine in ("ast", "both"):
        findings += scan_file(path)
    if engine in ("semgrep", "both"):
        findings += semgrep_adapter.scan_file(path)

    # De-duplicate: the same weakness seen by both engines is one finding.
    merged: dict[tuple[str, int], Finding] = {}
    for f in findings:
        merged.setdefault((f.rule_id, f.line), f)
    out = list(merged.values())
    out.sort(key=lambda f: (f.severity != Severity.CRITICAL, f.line))
    return out


def scan_file(path: str | Path) -> list[Finding]:
    """Built-in AST scanner only."""
    path = Path(path)
    source = path.read_text()
    lines = source.splitlines()
    tree = ast.parse(source)

    v = _Visitor(lines)
    v.visit(tree)
    raw = list(v.hits) + _scan_idor(tree, lines)

    findings: list[Finding] = []
    seen = set()
    for rule_id, line, snippet in raw:
        if (rule_id, line) in seen:
            continue
        seen.add((rule_id, line))
        sev, rationale = _SEVERITY[rule_id]
        findings.append(Finding(
            rule_id=rule_id,
            cwe=_CWE[rule_id],
            title=_TITLE[rule_id],
            severity=sev,
            severity_rationale=rationale,
            file=str(path),
            line=line,
            snippet=snippet,
            evidence="dynamic string reaches a dangerous sink"
                     if rule_id != "idor" else
                     "handler returns object without an ownership comparison",
        ))
    findings.sort(key=lambda f: (f.severity != Severity.CRITICAL, f.line))
    return findings
