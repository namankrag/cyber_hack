"""Minimal, real patches — the 'fix' step.

Each patch is expressed as exact source replacements against vulnbank/app.py,
plus a rationale. The verifier applies them to an isolated copy and generates a
unified diff, so what you see in the report is the actual change that was tested
— not a hand-waved description.

A deliberately BAD patch is included for VulnBank `sqli` to demonstrate the
verification gate rejecting a fix that blocks the exploit but breaks the
application.

Patches are looked up per fixture via :func:`patch_for` — the same rule id
can exist in several fixtures (e.g. `sqli` in both VulnBank and ShopAPI) with
fixture-specific anchors and diffs.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Patch:
    rule_id: str
    rationale: str
    # list of (old_substring, new_substring) applied in order
    replacements: list[tuple[str, str]] = field(default_factory=list)

    def apply(self, source: str) -> str:
        patched = source
        for old, new in self.replacements:
            if old not in patched:
                raise ValueError(
                    f"patch for {self.rule_id}: anchor not found:\n{old[:80]}..."
                )
            patched = patched.replace(old, new, 1)
        return patched


# --- SQLi: parameterize the query ----------------------------------------
PATCH_SQLI = Patch(
    rule_id="sqli",
    rationale="Use a parameterized query so user input is bound as data, "
              "never parsed as SQL. Closes CWE-89 without changing behaviour "
              "for legitimate credentials.",
    replacements=[(
        '''        # VULN[sqli]: CWE-89 — user input concatenated straight into SQL.
        query = (
            "SELECT * FROM users WHERE username = '%s' AND password = '%s'"
            % (username, password)
        )
        try:
            row = conn.execute(query).fetchone()''',
        '''        # FIX[sqli]: parameterized query — input is bound, not interpolated.
        try:
            row = conn.execute(
                "SELECT * FROM users WHERE username = ? AND password = ?",
                (username, password),
            ).fetchone()''',
    )],
)

# --- IDOR: enforce ownership ---------------------------------------------
PATCH_IDOR = Patch(
    rule_id="idor",
    rationale="Enforce that the account's owner_id matches the authenticated "
              "caller (admins exempt). Closes CWE-639; owners still read their "
              "own accounts unchanged.",
    replacements=[(
        '''        # VULN[idor]: CWE-639 — any authenticated user can read ANY account;
        # the handler never checks that the account belongs to the caller.
        return jsonify(''',
        '''        # FIX[idor]: ownership check — caller must own the account (or be admin).
        if acct["owner_id"] != user["id"] and user["role"] != "admin":
            return jsonify(error="forbidden"), 403
        return jsonify(''',
    )],
)

# --- Command injection: validate + no shell ------------------------------
PATCH_CMDI = Patch(
    rule_id="cmdi",
    rationale="Reject non-hostname input and call ping via an argument list "
              "(no shell), so metacharacters cannot start a new command. "
              "Closes CWE-78; legitimate hostnames still work. "
              "Verified portably: the echo runs through the Python interpreter "
              "(no echo binary needed), still with no shell and allow-listed input.",
    replacements=[(
        '''        # VULN[cmdi]: CWE-78 — user input flows into a shell command.
        output = os.popen("echo pinging " + host).read()''',
        '''        # FIX[cmdi]: validate input and avoid the shell (argument list).
        # PORTABILITY (SecureAI integration): echo via the interpreter rather
        # than an `echo` binary (Windows has no echo.exe); still no shell.
        import re as _re, subprocess as _sp, sys as _sys
        if not _re.fullmatch(r"[A-Za-z0-9_.-]+", host or ""):
            return jsonify(error="invalid host"), 400
        output = _sp.run([_sys.executable, "-c",
                          "import sys; print('pinging ' + sys.argv[1])", host],
                         capture_output=True, text=True, timeout=5).stdout''',
    )],
)

# --- Deliberately WEAK blocklist patches (for the BYPASSABLE demo) --------
# Each stops the canned probe but falls to a corpus variant; the Item-3 gate
# rejects them with "PATCH BYPASSABLE" naming the bypassing payload. They are
# exported for tests only and never enter FIXTURE_PATCHES, so the pipeline
# can never select them.
PATCH_SQLI_BLOCKLIST = Patch(
    rule_id="sqli",
    rationale="(Intentionally weak) Rejects only the exact known probe "
              "string — any rephrased tautology or UNION shape sails through.",
    replacements=[(
        '''        username = data.get("username", "")
        password = data.get("password", "")''',
        '''        username = data.get("username", "")
        password = data.get("password", "")
        # WEAK[sqli]: blocklist — rejects the exact known probe only.
        if username == "admin' --":
            return jsonify(error="invalid credentials"), 401''',
    )],
)

PATCH_CMDI_BLOCKLIST = Patch(
    rule_id="cmdi",
    rationale="(Intentionally weak) Rejects ';' and '|' only — &&, $(), "
              "backticks and newlines still start new commands.",
    replacements=[(
        '''        # VULN[cmdi]: CWE-78 — user input flows into a shell command.
        output = os.popen("echo pinging " + host).read()''',
        '''        # WEAK[cmdi]: blocklist — rejects ";" and "|" only.
        if ";" in host or "|" in host:
            return jsonify(error="invalid host"), 400
        output = os.popen("echo pinging " + host).read()''',
    )],
)

PATCH_XSS_BLOCKLIST = Patch(
    rule_id="xss",
    rationale="(Intentionally weak) Filters '<script' (case-insensitive) "
              "only — event-handler and svg vectors reflect untouched.",
    replacements=[(
        '''        # VULN[xss]: CWE-79 — user input reflected into HTML without escaping.
        return "<h1>Hello %s</h1>" % name''',
        '''        # WEAK[xss]: blocklist — filters "<script" only.
        if "<script" in name.lower():
            return "<h1>Hello traveller</h1>"
        return "<h1>Hello %s</h1>" % name''',
    )],
)

PATCH_PATHTRAV_BLOCKLIST = Patch(
    rule_id="pathtrav",
    rationale="(Intentionally weak) Rejects the exact known payload only — "
              "any rephrased traversal sails through.",
    replacements=[(
        '''        # VULN[pathtrav]: CWE-22 — user input used to build a filesystem path.
        content = open(docs_dir + "/" + name).read()''',
        '''        # WEAK[pathtrav]: blocklist — rejects the exact known payload.
        if name == "../vault_secret.txt":
            return jsonify(error="invalid path"), 400
        content = open(docs_dir + "/" + name).read()''',
    )],
)

#: Weak blocklist patches by rule id (test-only; never pipeline-selected).
WEAK_PATCHES = {
    "sqli": PATCH_SQLI_BLOCKLIST,
    "cmdi": PATCH_CMDI_BLOCKLIST,
    "xss": PATCH_XSS_BLOCKLIST,
    "pathtrav": PATCH_PATHTRAV_BLOCKLIST,
}


# --- A knowingly-broken patch (for the gate-rejection demo) ---------------
PATCH_SQLI_BAD = Patch(
    rule_id="sqli",
    rationale="(Intentionally bad) Blocks the exploit by rejecting ALL logins "
              "— kills functionality. The gate must reject this.",
    replacements=[(
        '''        if row is None:
            return jsonify(error="invalid credentials"), 401
        return jsonify(token=str(row["id"]), role=row["role"])''',
        '''        return jsonify(error="invalid credentials"), 401''',
    )],
)


# --- Path traversal: confine to the docs directory -----------------------
PATCH_PATHTRAV = Patch(
    rule_id="pathtrav",
    rationale="Resolve the requested path and confirm it stays inside the docs "
              "directory before opening it. Closes CWE-22; legitimate files in "
              "docs/ still load.",
    replacements=[(
        '''        # VULN[pathtrav]: CWE-22 — user input used to build a filesystem path.
        content = open(docs_dir + "/" + name).read()''',
        '''        # FIX[pathtrav]: resolve and confine the path to docs_dir.
        safe = os.path.normpath(os.path.join(docs_dir, name))
        if safe != docs_dir and not safe.startswith(docs_dir + os.sep):
            return jsonify(error="invalid path"), 400
        content = open(safe).read()''',
    )],
)

# --- XSS: escape reflected output ----------------------------------------
PATCH_XSS = Patch(
    rule_id="xss",
    rationale="HTML-escape user input before reflecting it. Closes CWE-79; the "
              "greeting still shows the name, now inert.",
    replacements=[(
        '''        # VULN[xss]: CWE-79 — user input reflected into HTML without escaping.
        return "<h1>Hello %s</h1>" % name''',
        '''        # FIX[xss]: escape user input before putting it in HTML.
        from markupsafe import escape as _escape
        return "<h1>Hello %s</h1>" % _escape(name)''',
    )],
)


PATCHES = {
    "sqli": PATCH_SQLI,
    "idor": PATCH_IDOR,
    "cmdi": PATCH_CMDI,
    "pathtrav": PATCH_PATHTRAV,
    "xss": PATCH_XSS,
}


# --- ShopAPI patches (FastAPI fixture) ------------------------------------
PATCH_SHOP_SQLI = Patch(
    rule_id="sqli",
    rationale="Use a parameterized query so user input is bound as data, "
              "never parsed as SQL. Closes CWE-89 without changing behaviour "
              "for legitimate credentials.",
    replacements=[(
        '''        # VULN[sqli]: CWE-89 — user input concatenated straight into SQL.
        query = (
            "SELECT * FROM users WHERE username = '%s' AND password = '%s'"
            % (username, password)
        )
        try:
            row = conn.execute(query).fetchone()''',
        '''        # FIX[sqli]: parameterized query — input is bound, not interpolated.
        try:
            row = conn.execute(
                "SELECT * FROM users WHERE username = ? AND password = ?",
                (username, password),
            ).fetchone()''',
    )],
)

PATCH_SHOP_PICKLE = Patch(
    rule_id="pickle",
    rationale="Disable the legacy pickle envelope: untrusted bytes must never "
              "reach pickle.loads (CWE-502). The JSON-native `data` document "
              "keeps working unchanged.",
    replacements=[(
        '''        if payload.blob is not None:
            # VULN[pickle]: CWE-502 — untrusted bytes handed to pickle.loads.
            try:
                obj = pickle.loads(base64.b64decode(payload.blob))
            except Exception:
                return JSONResponse({"error": "invalid blob"},
                                    status_code=400)
            return {"imported": str(obj), "type": type(obj).__name__}''',
        '''        if payload.blob is not None:
            # FIX[pickle]: legacy pickle envelope disabled — untrusted bytes
            # must never reach pickle.loads. Send the JSON-native `data`.
            return JSONResponse(
                {"error": "legacy pickle import disabled;"
                          " send JSON 'data' instead"},
                status_code=400)''',
    )],
)

PATCH_SHOP_SECRET = Patch(
    rule_id="secret",
    rationale="Read the expected key from the SHOPAPI_ADMIN_KEY environment "
              "variable and deny every caller when none is deployed, instead "
              "of trusting the hardcoded ADMIN_API_KEY literal (CWE-798). "
              "Rotate/delete the literal out-of-band.",
    replacements=[(
        '''        # VULN[secret]: CWE-798 — api_key is compared against the hardcoded
        # ADMIN_API_KEY module constant instead of a deployed secret.
        _ = request  # reserved for future per-request context
        if api_key != ADMIN_API_KEY:''',
        '''        # FIX[secret]: expected key comes from the environment; with none
        # deployed, deny every caller instead of trusting a source literal.
        _ = request  # reserved for future per-request context
        expected = os.environ.get("SHOPAPI_ADMIN_KEY", "")
        if not expected or api_key != expected:''',
    )],
)

SHOPAPI_PATCHES = {
    "sqli": PATCH_SHOP_SQLI,
    "pickle": PATCH_SHOP_PICKLE,
    "secret": PATCH_SHOP_SECRET,
}


#: Patches per fixture. VulnBank keeps the historic PATCHES table untouched;
#: ShopAPI adds its own. Rule ids may repeat across fixtures.
FIXTURE_PATCHES = {
    "vulnbank": PATCHES,
    "shopapi": SHOPAPI_PATCHES,
}


def _fixture_of(target: str | Path) -> str | None:
    from .manifest import fixture_id_for_path, load_manifest
    fixture = fixture_id_for_path(target)
    if fixture is None:
        stem = Path(target).stem
        if stem.endswith("_app"):
            candidate = stem[:-len("_app")]
            if candidate in load_manifest()["fixtures"]:
                fixture = candidate
    return fixture


def patch_for(target: str | Path, rule_id: str) -> Patch | None:
    """Return the curated patch for `rule_id` in the target's fixture."""
    fixture = _fixture_of(target)
    if fixture is None:
        return None
    return FIXTURE_PATCHES.get(fixture, {}).get(rule_id)
