"""ShopAPI — a second, deliberately vulnerable practice app (synthetic data only).

This is the IN-SCOPE target for the ShopAPI fixture. It is intentionally
insecure: three planted, CWE-tagged weaknesses live in the request handlers
below, each marked with a `# VULN:` comment. See shopapi/VULNERABILITIES.md.

Style contrast with VulnBank (the point of a second fixture): this app is
built on FastAPI with async handlers, Pydantic request models, and JSON
responses — instead of Flask with nested handlers and form-encoded flows.
PatchProof's per-CWE exploit/regression *templates* (parameterized by each
scanner finding's route, method, tainted parameter, and sink) work against
both styles with no hardcoded endpoints.

The module is self-contained (stdlib + fastapi only, in-memory DB seeded on
every create_app) so PatchProof can copy this single file, apply a candidate
patch to the copy, load it in isolation, and verify the result.

DO NOT deploy. Synthetic data, local use, security demonstration only.
"""
from __future__ import annotations

import base64
import os
import pickle
import sqlite3

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel


# VULN[secret]: CWE-798 — a live credential sitting in source. Anyone who can
# read this file can call the admin endpoint. (Synthetic value, local only.)
ADMIN_API_KEY = "sk-shop-synthetic-9f3a7c2e"


# --------------------------------------------------------------------------
# Synthetic data — three users and two products. No real PII.
# --------------------------------------------------------------------------
_SEED_USERS = [
    # id, username, password, role
    (1, "alice", "alice-pw", "user"),
    (2, "bob", "bob-pw", "user"),
    (3, "admin", "admin-pw", "admin"),
]
_SEED_PRODUCTS = [
    # sku, name, price
    ("WIDGET-1", "Widget", 25),
    ("GADGET-2", "Gadget", 40),
]


# DECOY[secret]: a revoked literal — still flagged by name, but presenting it
# is explicitly rejected (the key was rotated out-of-band).
LEGACY_API_KEY = "REVOKED-LEGACY-KEY-2024"


class LoginForm(BaseModel):
    username: str = ""
    password: str = ""


class OrderLookup(BaseModel):
    order_id: str = ""


class ImportPayload(BaseModel):
    # Legacy base64/pickle envelope, or the JSON-native `data` document.
    blob: str | None = None
    data: dict | None = None


def _init_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT);
        CREATE TABLE products (sku TEXT PRIMARY KEY, name TEXT, price INTEGER);
        """
    )
    conn.executemany("INSERT INTO users VALUES (?,?,?,?)", _SEED_USERS)
    conn.executemany("INSERT INTO products VALUES (?,?,?)", _SEED_PRODUCTS)
    conn.commit()
    return conn


def create_app() -> FastAPI:
    app = FastAPI(title="ShopAPI (synthetic practice app)")
    conn = _init_db()

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.post("/auth/login")
    async def login(form: LoginForm):
        username = form.username
        password = form.password
        # VULN[sqli]: CWE-89 — user input concatenated straight into SQL.
        query = (
            "SELECT * FROM users WHERE username = '%s' AND password = '%s'"
            % (username, password)
        )
        try:
            row = conn.execute(query).fetchone()
        except sqlite3.Error as exc:
            return JSONResponse({"error": f"query error: {exc}"}, status_code=400)
        if row is None:
            return JSONResponse({"error": "invalid credentials"}, status_code=401)
        return {"token": str(row["id"]), "role": row["role"]}

    @app.get("/products")
    async def list_products():
        rows = conn.execute("SELECT sku, name, price FROM products").fetchall()
        return {"products": [dict(r) for r in rows]}

    @app.post("/import")
    async def do_import(payload: ImportPayload):
        # The JSON-native envelope is the legitimate path.
        if payload.data is not None:
            items = payload.data.get("items", [])
            if not isinstance(items, list):
                return JSONResponse({"error": "items must be a list"},
                                    status_code=400)
            return {"imported": len(items), "items": items}
        if payload.blob is not None:
            # VULN[pickle]: CWE-502 — untrusted bytes handed to pickle.loads.
            try:
                obj = pickle.loads(base64.b64decode(payload.blob))
            except Exception:
                return JSONResponse({"error": "invalid blob"},
                                    status_code=400)
            return {"imported": str(obj), "type": type(obj).__name__}
        return JSONResponse({"error": "provide 'data' or 'blob'"},
                            status_code=400)

    @app.get("/admin/report")
    async def admin_report(request: Request, api_key: str = ""):
        # VULN[secret]: CWE-798 — api_key is compared against the hardcoded
        # ADMIN_API_KEY module constant instead of a deployed secret.
        _ = request  # reserved for future per-request context
        if api_key != ADMIN_API_KEY:
            return JSONResponse({"error": "forbidden"}, status_code=403)
        return {"currency": "SYNTH", "revenue": 12345, "orders": 7}

    # -- DECOYS: scanner-noisy shapes that exploits cannot confirm --------
    # Flagged by the AST scanner (and Semgrep where applicable) but resisting
    # the matching exploit template: the pipeline reports them NOT CONFIRMED
    # and drops them (raw alerts N -> confirmed M -> fixed K).
    @app.post("/orders/lookup")
    async def order_lookup(payload: OrderLookup):
        # DECOY[sqli]: int-cast — "%" formatting looks injectable, but only
        # integers ever reach the query.
        try:
            oid = int(payload.order_id)
        except (TypeError, ValueError):
            return JSONResponse({"error": "order id must be an integer"},
                                status_code=400)
        query = "SELECT * FROM users WHERE id = %d" % oid
        try:
            row = conn.execute(query).fetchone()
        except sqlite3.Error as exc:
            return JSONResponse({"error": f"query error: {exc}"},
                                status_code=400)
        if row is None:
            return JSONResponse({"error": "not found"}, status_code=404)
        return {"id": row["id"], "username": row["username"]}

    @app.post("/import/legacy")
    async def import_legacy(payload: ImportPayload):
        # DECOY[pickle]: loads() is still flagged, but only dict results are
        # honored — the marker-string proof is rejected as the wrong type.
        if payload.blob is None:
            return JSONResponse({"error": "provide 'blob'"},
                                status_code=400)
        try:
            obj = pickle.loads(base64.b64decode(payload.blob))
        except Exception:
            return JSONResponse({"error": "invalid blob"},
                                status_code=400)
        if not isinstance(obj, dict):
            return JSONResponse({"error": "legacy envelope restricted to maps"},
                                status_code=400)
        return {"imported": len(obj), "keys": sorted(obj)}

    @app.get("/legacy/report")
    async def legacy_report(api_key: str = ""):
        # DECOY[secret]: the revoked LEGACY_API_KEY literal is compared here
        # only to reject it explicitly — presenting it never grants access.
        if api_key == LEGACY_API_KEY:
            return JSONResponse({"error": "legacy key revoked"},
                                status_code=403)
        return JSONResponse({"error": "forbidden"}, status_code=403)

    return app


if __name__ == "__main__":  # pragma: no cover
    import uvicorn

    uvicorn.run(create_app(), port=5002)
