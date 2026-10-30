"""Minimal, real patches — the 'fix' step.

Each patch is expressed as exact source replacements against vulnbank/app.py,
plus a rationale. The verifier applies them to an isolated copy and generates a
unified diff, so what you see in the report is the actual change that was tested
— not a hand-waved description.

A deliberately BAD patch is included for `sqli` to demonstrate the verification
gate rejecting a fix that blocks the exploit but breaks the application.
"""
from __future__ import annotations

from dataclasses import dataclass, field


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
              "Closes CWE-78; legitimate hostnames still work.",
    replacements=[(
        '''        # VULN[cmdi]: CWE-78 — user input flows into a shell command.
        output = os.popen("echo pinging " + host).read()''',
        '''        # FIX[cmdi]: validate input and avoid the shell (argument list).
        import re as _re, subprocess as _sp
        if not _re.fullmatch(r"[A-Za-z0-9_.-]+", host or ""):
            return jsonify(error="invalid host"), 400
        output = _sp.run(["echo", "pinging", host], capture_output=True,
                         text=True, timeout=5).stdout''',
    )],
)

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
