# PatchProof — scope, safety, and limitations

PatchProof is a demonstrator for a verification-first find → prove → patch →
prove-fixed workflow. Read this before pointing it at anything.

## What it is for
The bundled practice fixtures — the **VulnBank** app (`vulnbank/`, Flask) and
the **ShopAPI** app (`shopapi/`, FastAPI) — and their documented, synthetic
vulnerabilities. All data is fake. In-scope files are listed per fixture in
its `VULNERABILITIES.md` (`vulnbank/app.py`, `shopapi/app.py`).

## Execution gate: the fixtures manifest (`fixtures.json`)
Exploits and candidate patches are executed **only** for files allowlisted in
the manifest, and only when their content matches the pinned sha256:

```json
{"version": 1,
 "fixtures": {"<fixture_id>": {"dir": "<subdir of patchproof/>",
                               "files": {"<file>": "<sha256>"}}}}
```

Concretely, `assert_bundled_fixture_target` allows a path iff (a) it sits
under a manifest-listed fixture dir **and** its bytes hash to the pinned
value, or (b) it is one of SecureAI's isolated remediation copies (a
temporary `vulnbank_app.py` / `shopapi_app.py` under a `secureai-remediation-*`
directory, used for verify-before-apply). Everything else raises `ValueError`
and nothing runs — fail-closed. After intentionally editing a fixture,
re-stamp its pin and review the diff before committing:

```bash
python -m patchproof.manifest --refresh   # re-stamp pins from disk
python -m patchproof.manifest --check     # verify pins match
```

## It runs real exploits and loads code — use only on trusted fixtures
To *prove* a finding, PatchProof executes a real exploit against the app, and
to verify a patch it imports and runs candidate source (including the OS-command
endpoint). This is safe for the bundled synthetic app but means:

- Run it only against code you trust / your own fixtures, in a sandbox.
- The command-injection demo executes shell commands (`echo`) — keep it local.
- AI-generated candidates are **parsed and validated** (must be valid Python and
  define the same function) before execution, but they are still executed; do
  not run untrusted targets outside a sandbox.

## Trust model for findings and patches
- A scanner finding is **not** trusted on its own. It is acted on only after an
  executable exploit **confirms** it (false positives are dropped).
- A patch — curated or AI-generated — is accepted **only** if the gate proves
  the exploit is blocked **and** the regression suite stays green. A patch that
  breaks functionality is rejected (`PATCH BREAKS APP`).
- AI patch generation is optional and fail-safe: no API key simply means no AI
  candidate; a missing or malformed response falls back to the curated patch.
- Content sent to the AI provider is the vulnerable function source — treat
  `--ai` as a deliberate data-sharing choice (a local model is a planned option).

## Limitations (what it does NOT claim)
- The built-in scanner covers seven CWE classes with intra-file heuristics; it is
  not a complete SAST. Semgrep is wired in as a second engine for breadth.
- Detection is best-effort; the **verification gate**, not the scanner, is the
  guarantee that matters.
- The verifier modifies only isolated copies — the target file is never changed
  by `scan`/`run` (apply-to-disk is a separate, explicit action).

## Deferred hardening
Local-model AI patcher (no egress) · more CWE classes and languages ·
CI gate (merge only on `FIXED & VERIFIED`) · richer regression generation ·
sandbox/isolation for running untrusted targets.
