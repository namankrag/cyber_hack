"""VulnBank — a deliberately vulnerable practice app (synthetic data only).

This is the IN-SCOPE target for PatchProof. It is intentionally insecure:
five planted, CWE-tagged weaknesses live in the request handlers below,
each marked with a `# VULN:` comment. See vulnbank/VULNERABILITIES.md.

The module is deliberately self-contained (stdlib + Flask only, in-memory DB
seeded on every create_app) so PatchProof can copy this single file, apply a
candidate patch to the copy, load it in isolation, and verify the result.

DO NOT deploy. Synthetic data, local use, security demonstration only.
"""
from __future__ import annotations

import os
import pathlib
import sqlite3
import tempfile

from flask import Flask, jsonify, request


# --------------------------------------------------------------------------
# Synthetic data — three users, each owning one account. No real PII.
# --------------------------------------------------------------------------
_SEED_USERS = [
    # id, username, password, role
    (1, "alice", "alice-pw", "user"),
    (2, "bob", "bob-pw", "user"),
    (3, "admin", "admin-pw", "admin"),
]
_SEED_ACCOUNTS = [
    # id, owner_id, balance, note
    (1001, 1, 4200, "Alice checking"),
    (1002, 2, 15750, "Bob savings"),
    (1003, 3, 0, "Admin ops"),
]


def _init_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT);
        CREATE TABLE accounts (id INTEGER PRIMARY KEY, owner_id INTEGER, balance INTEGER, note TEXT);
        """
    )
    conn.executemany("INSERT INTO users VALUES (?,?,?,?)", _SEED_USERS)
    conn.executemany("INSERT INTO accounts VALUES (?,?,?,?)", _SEED_ACCOUNTS)
    conn.commit()
    return conn


def _current_user(conn: sqlite3.Connection):
    """Resolve the caller from a 'Authorization: Bearer <user_id>' header.

    (A deliberately minimal auth scheme — the token is just the user id. The
    planted vulnerabilities are about what an *authenticated* user can then do.)
    """
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    uid = auth[len("Bearer "):].strip()
    if not uid.isdigit():
        return None
    row = conn.execute("SELECT * FROM users WHERE id = ?", (int(uid),)).fetchone()
    return row


def _init_docs() -> str:
    """A small document store: a public file in docs/, a secret one beside it."""
    base = tempfile.mkdtemp(prefix="vulnbank_")
    docs = os.path.join(base, "docs")
    os.makedirs(docs, exist_ok=True)
    pathlib.Path(docs, "welcome.txt").write_text(
        "Welcome to VulnBank. This document is public.\n")
    # Lives OUTSIDE docs/ — must not be reachable via the /files endpoint.
    pathlib.Path(base, "vault_secret.txt").write_text(
        "SYNTHETIC_SECRET_DO_NOT_LEAK=hunter2\n")
    return docs


def create_app() -> Flask:
    app = Flask(__name__)
    conn = _init_db()
    docs_dir = _init_docs()

    @app.get("/health")
    def health():
        return jsonify(status="ok")

    @app.post("/login")
    def login():
        data = request.get_json(silent=True) or {}
        username = data.get("username", "")
        password = data.get("password", "")
        # VULN[sqli]: CWE-89 — user input concatenated straight into SQL.
        query = (
            "SELECT * FROM users WHERE username = '%s' AND password = '%s'"
            % (username, password)
        )
        try:
            row = conn.execute(query).fetchone()
        except sqlite3.Error as exc:
            return jsonify(error=f"query error: {exc}"), 400
        if row is None:
            return jsonify(error="invalid credentials"), 401
        return jsonify(token=str(row["id"]), role=row["role"])

    @app.get("/accounts/<int:account_id>")
    def get_account(account_id: int):
        user = _current_user(conn)
        if user is None:
            return jsonify(error="unauthenticated"), 401
        acct = conn.execute(
            "SELECT * FROM accounts WHERE id = ?", (account_id,)
        ).fetchone()
        if acct is None:
            return jsonify(error="not found"), 404
        # VULN[idor]: CWE-639 — any authenticated user can read ANY account;
        # the handler never checks that the account belongs to the caller.
        return jsonify(
            id=acct["id"], owner_id=acct["owner_id"],
            balance=acct["balance"], note=acct["note"],
        )

    @app.post("/ping")
    def ping():
        user = _current_user(conn)
        if user is None:
            return jsonify(error="unauthenticated"), 401
        data = request.get_json(silent=True) or {}
        host = data.get("host", "")
        # VULN[cmdi]: CWE-78 — user input flows into a shell command.
        output = os.popen("echo pinging " + host).read()
        return jsonify(host=host, output=output)

    @app.get("/files")
    def read_file():
        name = request.args.get("name", "welcome.txt")
        # VULN[pathtrav]: CWE-22 — user input used to build a filesystem path.
        content = open(docs_dir + "/" + name).read()
        return jsonify(name=name, content=content)

    @app.get("/greet")
    def greet():
        name = request.args.get("name", "world")
        # VULN[xss]: CWE-79 — user input reflected into HTML without escaping.
        return "<h1>Hello %s</h1>" % name

    return app


if __name__ == "__main__":  # pragma: no cover
    create_app().run(port=5001)
