"""Regression suite + exploit harness.

These run against a Flask *test client*, so they need no network or ports and
are fully deterministic. Both pytest and the verification gate import these,
so "proof" means the same thing everywhere.

  * regression_suite(client)  -> legitimate behaviour that MUST keep working.
  * EXPLOITS[rule_id](client)  -> fires a real attack and reports if it worked.
"""
from __future__ import annotations

from .models import CheckResult, ExploitResult


# --------------------------------------------------------------------------
# Regression: legitimate functionality that a patch must NOT break.
# --------------------------------------------------------------------------
def regression_suite(client) -> list[CheckResult]:
    out: list[CheckResult] = []

    # Health endpoint up.
    r = client.get("/health")
    out.append(CheckResult("health_ok", r.status_code == 200, f"status={r.status_code}"))

    # A valid user can log in.
    r = client.post("/login", json={"username": "alice", "password": "alice-pw"})
    ok = r.status_code == 200 and r.get_json().get("token") == "1"
    out.append(CheckResult("valid_login_succeeds", ok, f"status={r.status_code}"))

    # Wrong password is rejected.
    r = client.post("/login", json={"username": "alice", "password": "nope"})
    out.append(CheckResult("bad_password_rejected", r.status_code == 401,
                           f"status={r.status_code}"))

    # A user can read their OWN account.
    r = client.get("/accounts/1001", headers={"Authorization": "Bearer 1"})
    ok = r.status_code == 200 and r.get_json().get("owner_id") == 1
    out.append(CheckResult("owner_reads_own_account", ok, f"status={r.status_code}"))

    # Legitimate ping works (host is a normal address).
    r = client.post("/ping", json={"host": "127.0.0.1"},
                    headers={"Authorization": "Bearer 1"})
    out.append(CheckResult("legit_ping_works", r.status_code == 200,
                           f"status={r.status_code}"))

    # A public document can be read.
    r = client.get("/files?name=welcome.txt")
    ok = r.status_code == 200 and "public" in (r.get_json() or {}).get("content", "")
    out.append(CheckResult("public_file_readable", ok, f"status={r.status_code}"))

    # Greeting renders the name.
    r = client.get("/greet?name=Alice")
    ok = r.status_code == 200 and "Hello Alice" in r.get_data(as_text=True)
    out.append(CheckResult("greet_works", ok, f"status={r.status_code}"))

    return out


# --------------------------------------------------------------------------
# Exploits: each returns exploited=True if the attack succeeded.
# --------------------------------------------------------------------------
def exploit_sqli(client) -> ExploitResult:
    # Comment out the password check and authenticate as admin.
    payload = {"username": "admin' --", "password": "wrong-on-purpose"}
    r = client.post("/login", json=payload)
    body = r.get_json() or {}
    exploited = r.status_code == 200 and body.get("role") == "admin"
    return ExploitResult(
        exploited,
        f"POST /login {payload} -> {r.status_code} {body}. "
        f"{'Authenticated as admin without the password.' if exploited else 'Blocked.'}",
    )


def exploit_idor(client) -> ExploitResult:
    # Alice (owner of 1001) tries to read Bob's account (1002).
    r = client.get("/accounts/1002", headers={"Authorization": "Bearer 1"})
    body = r.get_json() or {}
    exploited = r.status_code == 200 and body.get("owner_id") == 2
    return ExploitResult(
        exploited,
        f"GET /accounts/1002 as user 1 -> {r.status_code} {body}. "
        f"{'Read another users account.' if exploited else 'Access denied.'}",
    )


def exploit_cmdi(client) -> ExploitResult:
    # Inject a second command via a shell metacharacter.
    payload = {"host": "127.0.0.1; echo PWNED_BY_PATCHPROOF"}
    r = client.post("/ping", json=payload, headers={"Authorization": "Bearer 1"})
    body = r.get_json() or {}
    exploited = "PWNED_BY_PATCHPROOF" in (body.get("output", "") or "")
    return ExploitResult(
        exploited,
        f"POST /ping {payload} -> injected command "
        f"{'executed (output contained the marker).' if exploited else 'did not run.'}",
    )


def exploit_pathtrav(client) -> ExploitResult:
    # Escape the docs directory to read the sibling secret file.
    r = client.get("/files?name=../vault_secret.txt")
    body = r.get_json() or {}
    exploited = r.status_code == 200 and "SYNTHETIC_SECRET" in body.get("content", "")
    return ExploitResult(
        exploited,
        f"GET /files?name=../vault_secret.txt -> {r.status_code}. "
        f"{'Leaked a file outside the docs directory.' if exploited else 'Blocked.'}",
    )


def exploit_xss(client) -> ExploitResult:
    # Reflected payload returned unescaped = executable in a browser.
    payload = "<script>alert(document.cookie)</script>"
    r = client.get("/greet", query_string={"name": payload})
    text = r.get_data(as_text=True)
    exploited = payload in text          # raw, unescaped reflection
    return ExploitResult(
        exploited,
        f"GET /greet?name={payload} -> payload "
        f"{'reflected unescaped (executes in a browser).' if exploited else 'was escaped.'}",
    )


EXPLOITS = {
    "sqli": exploit_sqli,
    "idor": exploit_idor,
    "cmdi": exploit_cmdi,
    "pathtrav": exploit_pathtrav,
    "xss": exploit_xss,
}
