# ShopAPI — planted vulnerabilities (in-scope)

Synthetic practice app. All data is fake. Three deliberately planted
weaknesses are each exercised by an executable exploit and fixed by a minimal,
verified patch.

**In-scope file:** `shopapi/app.py` (the only file PatchProof scans and patches
for this fixture).

| ID | CWE | Class | Location (handler) | Severity |
|----|-----|-------|--------------------|----------|
| `sqli` | CWE-89 | SQL Injection (unsafe input handling) | `POST /auth/login` | Critical |
| `pickle` | CWE-502 | Deserialization of Untrusted Data | `POST /import` | Critical |
| `secret` | CWE-798 | Use of Hard-coded Credentials | `GET /admin/report` | High |

## Details

### sqli — SQL injection in login (CWE-89)
User-supplied `username`/`password` are concatenated directly into the SQL
string. Exploit: `username = "admin' --"` comments out the password check and
authenticates as admin. Fix: parameterized query. (Same CWE as VulnBank's
login, in FastAPI/async style — one per-CWE template covers both.)

### pickle — unsafe deserialization in /import (CWE-502)
The legacy `blob` envelope is base64-decoded and passed straight to
`pickle.loads`. Exploit: submit a crafted pickle that deserializes to the
marker string `PWNED_BY_PICKLE_502` (no shell, no imports — the payload only
calls the `str` builtin). Fix: reject the legacy `blob` envelope and accept
only the JSON-native `data` document.

### secret — hardcoded API key in /admin/report (CWE-798)
`GET /admin/report?api_key=...` compares the caller-supplied key against the
`ADMIN_API_KEY` module constant. Exploit: read the literal from the finding
and call the endpoint with it to receive the admin report. Fix: read the
expected key from the `SHOPAPI_ADMIN_KEY` environment variable and deny all
callers when it is unset.
