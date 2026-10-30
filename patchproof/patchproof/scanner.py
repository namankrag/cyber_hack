"""SAST scanner — the 'find' step.

A lightweight but real static analyzer built on Python's `ast`. It locates
weakness classes by their code shape and reports each with an exact
file:line, CWE, severity, the offending source snippet — plus the request
shape (route, HTTP method, tainted parameter, sink) so that exploits and
regression probes can be written as per-CWE *templates* parameterized by the
finding instead of hardcoding endpoints.

Design choice (mirrors the PS-02 problem): scanners are noisy. The scanner
here is intentionally conservative about *taint* — it flags a dangerous
shape, but PatchProof never trusts a finding on the scanner's word alone.
Every finding is independently confirmed by an executable exploit before it
is acted on (see the verifier). So a scanner false positive simply fails to
confirm and is dropped.

An optional Semgrep adapter is included for parity with real-world tooling;
the AST scanner is the default so the tool is self-contained.
"""
from __future__ import annotations

import ast
import re
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
    "pickle": (Severity.CRITICAL, "Deserializing untrusted input can execute "
                                  "arbitrary code; trivially exploitable, "
                                  "highest impact."),
    "secret": (Severity.HIGH, "Hardcoded credential: anyone reading the "
                              "source can impersonate the holder; "
                              "easy to exploit once leaked."),
}
_CWE = {"sqli": "CWE-89", "cmdi": "CWE-78", "idor": "CWE-639",
        "pathtrav": "CWE-22", "xss": "CWE-79",
        "pickle": "CWE-502", "secret": "CWE-798"}
_TITLE = {
    "sqli": "SQL injection: user input in SQL string",
    "cmdi": "OS command injection: user input in shell command",
    "idor": "Broken access control: object returned without ownership check",
    "pathtrav": "Path traversal: user input in a filesystem path",
    "xss": "Reflected XSS: user input returned in HTML unescaped",
    "pickle": "Unsafe deserialization: untrusted input passed to pickle",
    "secret": "Hardcoded credential used for authentication",
}

_ROUTE_METHODS = {"get": "GET", "post": "POST", "put": "PUT",
                 "delete": "DELETE", "patch": "PATCH",
                 "head": "HEAD", "options": "OPTIONS"}

# An assignment target that looks like a credential, e.g. ADMIN_API_KEY.
_SECRET_NAME_RE = re.compile(
    r"(^|_)(api[_-]?key|secret|token|passwd|password|private[_-]?key)(_|$)"
    r"|^(aws|github|stripe).*(key|secret)",
    re.IGNORECASE)


def _own_nodes(node: ast.AST) -> list[ast.AST]:
    """Nodes of one function body, not descending into nested defs/classes.

    Handlers are often nested inside a factory (Flask's `create_app`); a
    plain `ast.walk` from the outer function would attribute inner handlers'
    calls to the outer (routeless) scope and emit duplicate, shapeless hits.
    """
    out: list[ast.AST] = []

    def rec(current: ast.AST) -> None:
        for child in ast.iter_child_nodes(current):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef,
                                  ast.ClassDef)):
                continue
            out.append(child)
            rec(child)

    rec(node)
    return out


def _by_line(params: list[tuple[int, str]]) -> list[tuple[int, str]]:
    """Sort request params by source line; ties keep insertion order.

    Model fields are expanded in declaration order, so a same-line tie (e.g.
    `username`/`password` from one handler argument) resolves to the first
    declared field rather than alphabetical order.
    """
    return sorted(params, key=lambda p: p[0])


def _route_of(node: ast.FunctionDef) -> tuple[str, str]:
    """Extract (route, method) from Flask/FastAPI route decorators.

    Handles @app.get("/x"), @router.post("/x"), @bp.route("/x",
    methods=["POST"]) in either framework's style.
    """
    for dec in node.decorator_list:
        if not (isinstance(dec, ast.Call)
                and isinstance(dec.func, ast.Attribute)):
            continue
        kind = dec.func.attr.lower()
        if kind in _ROUTE_METHODS:
            if dec.args and isinstance(dec.args[0], ast.Constant):
                return str(dec.args[0].value), _ROUTE_METHODS[kind]
        elif kind == "route":
            path = ""
            if dec.args and isinstance(dec.args[0], ast.Constant):
                path = str(dec.args[0].value)
            method = "GET"
            for kw in dec.keywords:
                if (kw.arg == "methods"
                        and isinstance(kw.value, (ast.List, ast.Tuple))
                        and kw.value.elts
                        and isinstance(kw.value.elts[0], ast.Constant)):
                    method = str(kw.value.elts[0].value).upper()
            if path:
                return path, method
    return "", ""


def _class_fields(tree: ast.AST) -> dict[str, list[str]]:
    """Map local class names (e.g. Pydantic models) to their field names."""
    fields: dict[str, list[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            names: list[str] = []
            for sub in node.body:
                if isinstance(sub, ast.AnnAssign) and isinstance(sub.target, ast.Name):
                    if sub.target.id not in names:
                        names.append(sub.target.id)
                elif (isinstance(sub, ast.Assign)
                      and len(sub.targets) == 1
                      and isinstance(sub.targets[0], ast.Name)):
                    if sub.targets[0].id not in names:
                        names.append(sub.targets[0].id)
            fields[node.name] = names
    return fields


def _is_request(node: ast.AST) -> bool:
    return isinstance(node, ast.Name) and node.id == "request"


def _is_request_obj(node: ast.AST) -> bool:
    """request.args / request.form / request.values / request.query_params."""
    return (isinstance(node, ast.Attribute)
            and node.attr in ("args", "form", "values", "query_params")
            and _is_request(node.value))


class _Visitor(ast.NodeVisitor):
    """Per-function pass with a tiny intra-procedural taint set.

    A variable assigned a dynamic string (f-string / concat / %-format) is
    marked tainted; a `.execute(var)` or shell call on a tainted var — or on a
    dynamic string directly — is flagged. This catches the common real pattern
    where the query is built on one line and executed on the next.

    Each hit also records the handler's route, HTTP method, the tainted
    request parameter, and the sink, so downstream templates need no
    hardcoded endpoints.
    """

    def __init__(self, source_lines: list[str],
                 class_fields: dict[str, list[str]]) -> None:
        self.lines = source_lines
        self.class_fields = class_fields
        # (rule_id, line, snippet, param, sink, route, method)
        self.hits: list[tuple[str, int, str, str, str, str, str]] = []

    # -- per-function entry ---------------------------------------------
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)
        self.generic_visit(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        route, method = _route_of(node)
        tainted: set[str] = set()
        assign_names: dict[str, set[str]] = {}
        for n in _own_nodes(node):
            if isinstance(n, ast.Assign) and _is_dynamic_string(n.value):
                names = {t.id for t in ast.walk(n.value)
                         if isinstance(t, ast.Name)}
                for t in n.targets:
                    if isinstance(t, ast.Name):
                        tainted.add(t.id)
                        assign_names.setdefault(t.id, set()).update(names)
        req_params = _request_params(node, self.class_fields)
        req_set = {p for _, p in req_params}

        def tainted_param(arg: ast.AST) -> str:
            names: set[str] = set()
            if isinstance(arg, ast.Name) and arg.id in tainted:
                names.update(assign_names.get(arg.id, set()))
            names.update(n.id for n in ast.walk(arg)
                         if isinstance(n, ast.Name))
            for _, p in _by_line(req_params):
                if p in names:
                    return p
            # The taint came from this request even if the exact field could
            # not be pinned down: attribute it to the handler's first input.
            if names and req_params:
                return _by_line(req_params)[0][1]
            return ""

        for n in _own_nodes(node):
            if isinstance(n, ast.Call):
                self._check_sqli(n, tainted, tainted_param, route, method)
                self._check_cmdi(n, tainted, tainted_param, route, method)
                self._check_pathtrav(n, tainted, tainted_param, route, method)
                self._check_pickle(n, route, method, req_params)
            if isinstance(n, ast.Return) and n.value is not None:
                self._check_xss(n, tainted_param, route, method)
        self._check_idor(node, route, method, req_params, req_set)

    # -- per-shape checks ------------------------------------------------
    def _emit(self, rule_id: str, line: int, param: str, sink: str,
              route: str, method: str) -> None:
        self.hits.append(
            (rule_id, line, self._src(line), param, sink, route, method))

    def _check_sqli(self, node: ast.Call, tainted: set[str],
                    tainted_param, route: str, method: str) -> None:
        if not (isinstance(node.func, ast.Attribute) and node.func.attr == "execute"):
            return
        if node.args and self._tainted_arg(node.args[0], tainted):
            name = _dotted(node.func)
            self._emit("sqli", node.lineno, tainted_param(node.args[0]),
                       name or "db.execute", route, method)

    def _check_cmdi(self, node: ast.Call, tainted: set[str],
                    tainted_param, route: str, method: str) -> None:
        name = _dotted(node.func)
        if name in {"os.system", "os.popen", "subprocess.call",
                    "subprocess.run", "subprocess.Popen"}:
            if node.args and self._tainted_arg(node.args[0], tainted):
                self._emit("cmdi", node.lineno, tainted_param(node.args[0]),
                           name, route, method)

    def _check_pathtrav(self, node: ast.Call, tainted: set[str],
                        tainted_param, route: str, method: str) -> None:
        # open(<dynamic path>) with user-influenced input.
        if isinstance(node.func, ast.Name) and node.func.id == "open":
            if node.args and self._tainted_arg(node.args[0], tainted):
                self._emit("pathtrav", node.lineno,
                           tainted_param(node.args[0]), "open", route, method)

    def _check_xss(self, node: ast.Return, tainted_param,
                   route: str, method: str) -> None:
        # A handler returning a dynamic string that looks like HTML (contains a
        # tag) with no escaping is a reflected-XSS candidate.
        if _is_dynamic_string(node.value):
            line = self._src(node.lineno)
            if "<" in line and "escape" not in line:
                self._emit("xss", node.lineno, tainted_param(node.value),
                           "unescaped-html-return", route, method)

    def _check_pickle(self, node: ast.Call, route: str, method: str,
                      req_params: list[tuple[int, str]]) -> None:
        # pickle.loads(<non-literal>) / yaml.load(<non-literal>, no Loader)
        # on request-influenced data is CWE-502.
        name = _dotted(node.func)
        is_pickle = name in {"pickle.loads", "pickle.load"}
        is_yaml = (name == "yaml.load"
                   and not any(kw.arg == "Loader" for kw in node.keywords))
        if not (is_pickle or is_yaml):
            return
        if not node.args or isinstance(node.args[0], ast.Constant):
            return
        arg_names = {n.id for n in ast.walk(node.args[0])
                     if isinstance(n, ast.Name)}
        param = ""
        for _, p in _by_line(req_params):
            if p in arg_names:
                param = p
                break
        if not param and req_params:
            param = _by_line(req_params)[0][1]
        self._emit("pickle", node.lineno, param, name, route, method)

    def _check_idor(self, node: ast.FunctionDef | ast.AsyncFunctionDef,
                    route: str, method: str,
                    req_params: list[tuple[int, str]], req_set: set[str]) -> None:
        """Generalized authz heuristic: a handler on an object route (one with
        a path placeholder in either framework's style) that returns a record
        without ever comparing the record's owner to the current user.

        (Real authz detection is hard for generic SAST; this is a targeted,
        explainable heuristic. As with every finding, it only matters once the
        exploit confirms it.)
        """
        if not route or ("<" not in route and "{" not in route):
            return
        body_src = "\n".join(self.lines[node.lineno - 1:node.end_lineno])
        if "owner_id" not in body_src and "owner" not in body_src:
            return
        has_owner_check = ("owner_id" in body_src and "user" in body_src
                           and ("!=" in body_src or "==" in body_src
                                or "authorize" in body_src))
        if not has_owner_check:
            param = _by_line(req_params)[0][1] if req_params else ""
            self._emit("idor", node.lineno, param,
                       "missing-ownership-check", route, method or "GET")

    def _tainted_arg(self, arg: ast.AST, tainted: set[str]) -> bool:
        if _is_dynamic_string(arg):
            return True
        return isinstance(arg, ast.Name) and arg.id in tainted

    def _src(self, lineno: int) -> str:
        return self.lines[lineno - 1].strip() if 0 < lineno <= len(self.lines) else ""


def _request_params(node: ast.FunctionDef | ast.AsyncFunctionDef,
                    class_fields: dict[str, list[str]]
                    ) -> list[tuple[int, str]]:
    """Ordered (line, name) request-controlled inputs of one handler.

    Covers Flask (`request.args.get("k")`, `data.get("k")` after
    `request.get_json()`) and FastAPI (handler arguments, expanded through
    local Pydantic models) styles.
    """
    params: list[tuple[int, str]] = []

    def add(lineno: int, name: str) -> None:
        if name and all(p != name for _, p in params):
            params.append((lineno, name))

    json_holders: set[str] = set()
    for sub in _own_nodes(node):
        target: ast.AST | None = None
        value: ast.AST | None = None
        if isinstance(sub, ast.Assign) and len(sub.targets) == 1:
            target, value = sub.targets[0], sub.value
        elif isinstance(sub, ast.AnnAssign) and sub.value is not None:
            target, value = sub.target, sub.value
        if target is None or value is None or not isinstance(target, ast.Name):
            continue
        val = value
        if isinstance(val, ast.Await):
            val = val.value
        if isinstance(val, ast.BoolOp) and val.values:
            # e.g. `data = request.get_json(silent=True) or {}`
            first = val.values[0]
            val = first.value if isinstance(first, ast.Await) else first
        if isinstance(val, ast.Call) and isinstance(val.func, ast.Attribute):
            recv = val.func
            # data = request.get_json(...) / request.json()
            if _is_request(recv.value) and recv.attr in ("get_json", "json"):
                json_holders.add(target.id)
            # x = request.args.get("k") / request.form.get("k") / ...
            elif _is_request_obj(recv.value) and recv.attr == "get":
                if val.args and isinstance(val.args[0], ast.Constant):
                    add(sub.lineno, str(val.args[0].value))
            # x = (await request.json()).get("k") — handled below via holders
        # x = request.args["k"] / request.form["k"]
        if (isinstance(val, ast.Subscript)
                and _is_request_obj(val.value)
                and isinstance(val.slice, ast.Constant)):
            add(sub.lineno, str(val.slice.value))
        # y = data.get("k") / data["k"] where data holds the JSON body
        if json_holders:
            if (isinstance(val, ast.Call) and isinstance(val.func, ast.Attribute)
                    and isinstance(val.func.value, ast.Name)
                    and val.func.value.id in json_holders
                    and val.func.attr == "get"
                    and val.args and isinstance(val.args[0], ast.Constant)):
                add(sub.lineno, str(val.args[0].value))
            elif (isinstance(val, ast.Subscript)
                  and isinstance(val.value, ast.Name)
                  and val.value.id in json_holders
                  and isinstance(val.slice, ast.Constant)):
                add(sub.lineno, str(val.slice.value))

    # FastAPI-style handler arguments (also covers Flask path params such as
    # `def get_account(account_id: int)`): each argument is request input,
    # expanded through local model classes when annotated with one.
    all_args = list(node.args.args) + list(node.args.kwonlyargs)
    for arg in all_args:
        if arg.arg in ("self", "cls", "request"):
            continue
        # Unwrap Optional[X] / X | None so a nullable model still expands
        # to its fields (e.g. `payload: ImportPayload | None` -> blob, data).
        ann_names = {n.id for n in ast.walk(arg.annotation)
                     if isinstance(n, ast.Name)} \
            if arg.annotation is not None else set()
        models = [n for n in ann_names if n in class_fields]
        if models:
            for model in models:
                for field_name in class_fields[model]:
                    add(arg.lineno, field_name)
        elif arg.arg not in ("conn", "db", "session"):
            add(arg.lineno, arg.arg)
    return params


def _scan_secrets(tree: ast.AST, lines: list[str],
                  routes: dict[str, tuple[str, str, list[tuple[int, str]]]]
                  ) -> list[tuple[str, int, str, str, str, str, str]]:
    """CWE-798: module-level `*_KEY = "<literal>"` style credentials that a
    request handler compares against. Returns hits shaped like _Visitor.hits.
    """
    # Only module-level assignments count as "hardcoded": a literal defined
    # next to the code (not derived per request) that a handler trusts.
    secrets: list[tuple[str, str, int]] = []  # (name, literal, line)
    for node in getattr(tree, "body", []):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
            if isinstance(node.value.value, str) and len(node.value.value) >= 4:
                for t in node.targets:
                    if (isinstance(t, ast.Name)
                            and _SECRET_NAME_RE.search(t.id)):
                        secrets.append((t.id, node.value.value, node.lineno))
    hits = []
    for name, _literal, lineno in secrets:
        snippet = lines[lineno - 1].strip() if 0 < lineno <= len(lines) else ""
        for func_name, shape in routes.items():
            route, method, req_params, start, end = shape
            body = "\n".join(lines[start - 1:end])
            if name in body and route:
                param = _by_line(req_params)[0][1] if req_params else ""
                hits.append(("secret", lineno, snippet, param,
                             "hardcoded-credential", route, method or "GET"))
                break
    return hits


def _is_dynamic_string(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):      # f"...{x}..."
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


def _function_routes(tree: ast.AST,
                     class_fields: dict[str, list[str]]
                     ) -> dict[str, tuple[str, str, list[tuple[int, str]], int, int]]:
    """Map function name -> (route, method, req_params, lineno, end_lineno)."""
    out = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            route, method = _route_of(node)
            out[node.name] = (route, method,
                              _request_params(node, class_fields),
                              node.lineno, node.end_lineno)
    return out


def scan_text(source: str, filename: str = "<memory>") -> list[Finding]:
    """Scan Python source text (used for in-memory patched copies too)."""
    lines = source.splitlines()
    tree = ast.parse(source)
    class_fields = _class_fields(tree)

    v = _Visitor(lines, class_fields)
    v.visit(tree)
    routes = _function_routes(tree, class_fields)
    raw = list(v.hits) + _scan_secrets(tree, lines, routes)

    findings: list[Finding] = []
    seen = set()
    for rule_id, line, snippet, param, sink, route, method in raw:
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
            file=filename,
            line=line,
            snippet=snippet,
            evidence="dynamic string reaches a dangerous sink"
                     if rule_id not in ("idor", "secret") else
                     ("handler returns object without an ownership comparison"
                      if rule_id == "idor" else
                      "hardcoded credential compared against request input"),
            route=route,
            method=method,
            param=param,
            sink=sink,
        ))
    findings.sort(key=lambda f: (f.severity != Severity.CRITICAL, f.line))
    return findings


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
        try:
            findings += semgrep_adapter.scan_file(path)
        except Exception:
            # Semgrep unavailable/broken in this env (e.g. mcp version clash).
            # "both"/"auto" degrade to AST; "semgrep" alone re-raises.
            if engine == "semgrep":
                raise

    # De-duplicate: the same weakness seen by both engines is one finding.
    # The AST finding wins so the request shape (route/method/param/sink)
    # survives a Semgrep duplicate; a Semgrep-only finding is enriched from
    # the AST pass when it matches the same rule and line.
    merged: dict[tuple[str, int], Finding] = {}
    for f in findings:
        merged.setdefault((f.rule_id, f.line), f)
    ast_shapes = {(f.rule_id, f.line): f for f in findings if f.route}
    for key, f in merged.items():
        if not f.route and key in ast_shapes:
            shape = ast_shapes[key]
            f.route, f.method, f.param, f.sink = (
                shape.route, shape.method, shape.param, shape.sink)
    out = list(merged.values())
    out.sort(key=lambda f: (f.severity != Severity.CRITICAL, f.line))
    return out


def scan_file(path: str | Path) -> list[Finding]:
    """Built-in AST scanner only."""
    path = Path(path)
    return scan_text(path.read_text(encoding="utf-8"), filename=str(path))
