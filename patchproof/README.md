# 🛡️ PatchProof

**Find the flaw. Prove the fix.**

A verification-first pipeline for deliberately vulnerable software. It doesn't
just flag weaknesses and suggest patches — it **proves** each finding is real
with a working exploit, and accepts a fix only if that fix **blocks the exploit
while the app's functionality stays green.**

The problem it answers (PS-02 / PATCHPROOF): scanners are noisy and remediation
can break things. Smaller teams need *evidence* that a finding is real and that
a patch removes the weakness without regressions. PatchProof makes that evidence
the whole product.

## The loop

```
  FIND            PROVE                 PATCH            PROVE-FIXED
  (SAST)          (exploit)             (minimal diff)   (gate)
  ───────         ─────────────         ─────────        ─────────────────────
  scan source  →  run a real exploit →  apply fix on  →  exploit now BLOCKED
  file:line,      against the running   an isolated      AND regression suite
  CWE, severity   app; drop it if it    copy; emit a     still GREEN  → accept
                  can't be exploited    unified diff     (else reject the patch)
```

A finding the exploit can't confirm is treated as a **false positive and
dropped**. A patch that blocks the exploit but **breaks a feature is rejected**
(verdict: `PATCH BREAKS APP`). Only `FIXED & VERIFIED` means both halves proved.

## Quickstart

```bash
pip install -r requirements.txt

# Full pipeline on the vulnerable app + report.html / report.json
python -m examples.run_demo

# Or use the CLI
python -m patchproof scan vulnbank/app.py --engine both
python -m patchproof run  vulnbank/app.py --report report.html
python -m patchproof run  vulnbank/app.py --ai         # AI-generated patches (needs a key)

# Tests (scanner, exploits, the gate incl. a rejected patch, engines, AI flow, CLI)
python -m pytest -q
```

The core and curated patches need **no API keys**. AI patch generation needs a
free **Gemini** or **Groq** key (see `.env.example`); without one it falls back
to curated patches.

## What's in the box

| Part | Path | Role |
|---|---|---|
| Target app (in-scope) | `vulnbank/app.py` | deliberately vulnerable Flask app; synthetic data |
| Vuln docs | `vulnbank/VULNERABILITIES.md` | the planted weaknesses + CWE + in-scope file |
| Scanner (find) | `patchproof/scanner.py` | AST-based SAST; findings with file:line, CWE, severity |
| Exploits (prove) | `patchproof/checks.py` | executable attacks that confirm each finding is real |
| Patches (fix) | `patchproof/patches.py` | minimal real diffs + a deliberately-breaking one |
| Verifier (gate) | `patchproof/verifier.py` | runs exploit + regression before/after on isolated copies |
| Pipeline | `patchproof/pipeline.py` | orchestrates find → prove → patch → prove-fixed |
| Report | `patchproof/report.py` | HTML + JSON: severity, location, diff, test status |

## The five planted weaknesses

| CWE | Class | Exploit | Fix |
|---|---|---|---|
| CWE-89 | SQL injection | `username = "admin' --"` bypasses auth | parameterized query |
| CWE-78 | OS command injection | `host = "x; echo PWNED"` runs a 2nd command | validate + no shell |
| CWE-639 | Broken access control (IDOR) | read another user's account by id | ownership check |
| CWE-22 | Path traversal | `name = "../vault_secret.txt"` leaks a file | confine path to docs/ |
| CWE-79 | Reflected XSS | `name = "<script>…"` reflected unescaped | HTML-escape output |

## Scanners (the "find" step)

Pluggable engines, selected with `--engine`:
- **ast** — built-in analyzer with a small intra-file taint pass (always available).
- **semgrep** — the industry-standard SAST engine, run offline with local rules.
- **both / auto** — union of both, de-duplicated (auto uses both when Semgrep is installed).

## AI-assisted patching (the honest way to use an LLM)

With `--ai`, PatchProof asks a model (Gemini/Groq) to **write** a fix for the
vulnerable function — then runs that generated code through the **same
verification gate**. The AI patch is accepted only if it blocks the exploit and
keeps the regression suite green; otherwise it's rejected and the curated patch
is used. The AI proposes; the gate decides. (Candidates are parsed and validated
before execution; a missing key just means no AI candidate.)

## Why this stands out

Most tools stop at "scanner found X, here's a patch." PatchProof shows **evidence
on both ends**: a live exploit that proves the bug is real (killing false-positive
noise), and a patch proven to kill that exploit **without breaking the app**
(a regression suite that stays green). The verification gate — accept only if the
exploit flips to blocked *and* functionality is preserved — is the differentiator.

Safety: all data is synthetic; the pipeline patches **copies**, never the live
source, so the demo is reproducible and the target stays pristine.

## Scaling path

Swap the built-in AST scanner for **Semgrep/CodeQL** (adapter stub included);
add more CWE classes; wire the accepted diffs into CI as a gate (a PR only merges
if PatchProof returns `FIXED & VERIFIED`); AI-assisted patch generation can slot
in as a patch source, still subject to the same gate.
