# 🛡️ SecureAI Platform — guard the agent + harden its tools

SecureAI unifies the two projects in this repo into one security platform for
AI agents, defending at **two layers**:

- **Runtime — AgentShield (PS-1).** Guards a *running* agent at the tool-call
  boundary: allow / hold-for-approval / block, with inspectable reasons.
- **Code — PatchProof (PS-2).** Finds, exploit-confirms, patches, and verifies
  vulnerabilities in the *code the agent's tools run on*.

The integration layer lives in [`secureai/`](secureai/).

## Why together (not two unrelated tools)

AgentShield decides **which tool calls are allowed**. Those tools are *code* —
and tool/MCP-server code is a common source of real vulnerabilities. SecureAI
defends the **same asset from both sides**:

```
   Agent ──calls──►  [ AgentShield ]  ──allowed──►  Tool
                     runtime boundary               (its code)
                           │                           ▲
                      blocks attack                    │
                           │                    [ PatchProof ]
                           └────── bridge ──────► scan • prove • patch • verify
```

### The bridge (`secureai/bridge.py`)
1. **harden_tools()** — runs PatchProof over the implementation of the tools
   AgentShield governs (a tool→source registry maps each tool to its file).
2. **runtime → code loop** — when AgentShield **blocks** an attack aimed at a
   tool, the bridge automatically scans that tool's source for the root cause
   and surfaces a verified fix, linked back to the runtime block.

### The shared core (`secureai/core.py`)
Both layers already produce an inspectable, evidence-backed verdict. The core
maps an AgentShield `EnforcementResult` and a PatchProof `IssueReport` onto one
`SecurityEvent`, so a single store and dashboard render both.

## Run it

```bash
pip install -r requirements.txt          # single root requirements (incl. flask)
# Reproducible, hash-pinned alternative:
pip install -e .                         # optional: the `secureai` console script (pyproject); `python -m secureai` works with no install

# The `secureai` console script (pyproject) and `python -m secureai` are
# equivalent - the latter needs no install. `--engine` defaults to `auto`
# (AST scanner when Semgrep is unavailable); `--report` / `--out-dir`
# take explicit paths.

# The flagship: run both layers + the bridge, write the unified dashboard
python -m secureai platform --report reports/platform_dashboard.html

# Just one layer
python -m secureai runtime                # AgentShield scenarios
python -m secureai harden                 # PatchProof over the governed tools

# Closed remediation loop: block → bridge scan → patch → verify → re-attack
secureai loop --max-iters 8 --report reports/loop_report.json

# One evaluation pass or a bounded decision-threshold search
secureai eval --once --out-dir reports
secureai eval --tune --out-dir reports/tuned

# Re-evaluate when the bundled practice tool changes
secureai watch --interval 1 --out-dir reports

# Tests - one suite from the repo root (collects tests/ + patchproof/tests/)
pytest -q
# -> 178 passed, 1 skipped (the skip is the Semgrep-engine test;
#    Semgrep is not installed, so the platform uses its graceful AST fallback)
```

`secureai eval` writes `scorecard.json` and `scorecard.html`; it exits nonzero
when any acceptance gate fails. At the selected threshold 0.5 the scorecard passes 8/8 gates (the tune search shows 0.35/0.40/0.45 each fail one gate). The report contains per-scenario decisions,
independent code rechecks, regression status, and the confirmed-vulnerability
count at each loop iteration. The synthetic dataset covers direct and indirect
injection, a disabled tool, benign calls, and a legitimate high-impact action
that must be held for approval.

The remediation loop applies patches only to a temporary VulnBank copy. Each
exploit and regression job runs in a child process with a 10-second deadline.
The runtime policy is re-attacked before and after each accepted patch, and the
bridge links those runtime blocks to AST findings in the same copy. An
unverified patch stops with `approval_required`; the source fixture is never
auto-modified.

## What a run shows

- **Runtime:** a legit `search_web` is allowed, an injected `read_customer_db`
  is **blocked**, a genuine `send_email` is **held for approval**.
- **Bridge:** the block on `read_customer_db` auto-triggers a code scan of its
  backing service.
- **Code:** PatchProof confirms + patches + verifies **5 CWE classes**
  (SQLi, command injection, IDOR, path traversal, XSS) in that service.
- **Dashboard:** one page, two columns, with each code fix linked to the
  runtime block that triggered it.

## Note on Semgrep + the MCP SDK (dependency isolation)

AgentShield's MCP gateway needs `mcp` **2.x**; the Semgrep CLI currently imports
an `mcp` **1.x** module at startup. Both can't load in one environment. The
platform resolves this gracefully: it keeps `mcp` 2.x, and PatchProof's Semgrep
adapter **probes whether Semgrep actually runs** and auto-falls back to the
built-in AST scanner when it can't (the AST engine covers all five CWE classes,
so nothing is lost). To use Semgrep as a second engine, run PatchProof in its
own virtualenv (`patchproof/`), where `mcp` 1.x and Semgrep coexist — the
standard monorepo answer of one venv per subproject.

## Layout (branch `muse-secureai-integration`)

```
agentshield/        PS-1 — hardened MUSE runtime: enforcement + approvals/RAG/MCP/rate-limit/docs-gate
patchproof/         PS-2 — find/prove/patch/verify
secureai/           integration: core.py · bridge.py · platform.py · dashboard.py · cli.py
                    loop.py · evaluation.py · grader.py
```
