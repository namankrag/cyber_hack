# VulnBank — planted vulnerabilities (in-scope)

Synthetic practice app. All data is fake. Five deliberately planted
weaknesses are each exercised by an executable exploit and fixed by a minimal,
verified patch.

**In-scope file:** `vulnbank/app.py` (the only file PatchProof scans and patches).

| ID | CWE | Class | Location (handler) | Severity |
|----|-----|-------|--------------------|----------|
| `sqli` | CWE-89 | SQL Injection (unsafe input handling) | `POST /login` | Critical |
| `idor` | CWE-639 | Broken Access Control / IDOR | `GET /accounts/<id>` | High |
| `cmdi` | CWE-78 | OS Command Injection | `POST /ping` | Critical |
| `pathtrav` | CWE-22 | Path Traversal | `GET /files` | High |
| `xss` | CWE-79 | Reflected Cross-Site Scripting | `GET /greet` | Medium |

## Details

### sqli — SQL injection in login (CWE-89)
User-supplied `username`/`password` are concatenated directly into the SQL
string. Exploit: `username = "admin' --"` comments out the password check and
authenticates as admin. Fix: parameterized query.

### idor — Insecure Direct Object Reference (CWE-639)
`GET /accounts/<id>` returns any account by id to any authenticated user; it
never checks ownership. Exploit: Alice (owner of 1001) reads Bob's account
1002. Fix: enforce that the account's `owner_id` matches the caller (or the
caller is an admin).

### cmdi — OS command injection in /ping (CWE-78)
The `host` field is concatenated into a shell command. Exploit:
`host = "127.0.0.1; echo PWNED"` runs arbitrary commands. Fix: validate input
and avoid the shell (argument list).

### pathtrav — Path traversal in /files (CWE-22)
The requested filename is joined to the docs directory without confinement.
Exploit: request `../vault_secret.txt` to read a sibling synthetic file. Fix:
normalize and confine the resolved path to the docs directory.

### xss — Reflected XSS in /greet (CWE-79)
The name query parameter is interpolated into an HTML response without
escaping. Exploit: submit a script tag and observe it returned as active markup.
Fix: HTML-escape the value before rendering.

## Decoys — scanner noise the exploits cannot confirm

Realistic look-alikes the AST scanner (and Semgrep where applicable) still
flag, but every exploit template fails against, so the pipeline marks them
NOT CONFIRMED and drops them without a patch. Each scans as `<rule>-decoy`
(same CWE, distinct rule id) so per-finding proofs stay unambiguous.
They pin the noise funnel:
raw alerts 10 → confirmed 5 → fixed 5 (precision 50% → 100%).

| ID | CWE | Shape | Why the scanner flags it | Why the exploit fails |
|----|-----|-------|--------------------------|-----------------------|
| `sqli-decoy` | CWE-89 | `POST /search` | `"..." % uid` reaches `conn.execute` | `q` is `int()`-cast; `admin' --` → 400 |
| `cmdi-decoy` | CWE-78 | `POST /ping-safe` | `"..." + host` reaches `os.popen` | allowlist rejects `; echo …` → 400 |
| `pathtrav-decoy` | CWE-22 | `GET /docs` | `open(docs_dir + "/" + name)` is dynamic | `realpath` confinement rejects `../` → 400 |
| `xss-decoy` | CWE-79 | `GET /hello` | `return "<h1>…%s…</h1>" % safe`, no `escape` on that line | value escaped on its own line; probe returns inert |
| `idor-decoy` | CWE-639 | `GET /accounts/<id>/statement` | object route + `owner_id` with no inline comparison | `_owns()` helper enforces ownership; Alice → 403 on Bob's account |
