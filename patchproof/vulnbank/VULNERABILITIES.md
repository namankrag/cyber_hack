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
