# PatchProof — 3-minute demo (PS-02 first, SecureAI closes)

All commands run offline on synthetic fixtures. No API keys. Write demo
artifacts to `/tmp` so the repo's `reports/` stays pristine.

## 0:00–0:25 — The problem: scanners are noisy, patches are unproven

Say: scanners flag everything, and every "fix" is a guess until something
proves it. Show the noise first:

```bash
PYTHONPATH=patchproof python -m patchproof scan patchproof/vulnbank/app.py --engine ast
```

Point: 10 alerts on one small app. Nobody patches 10 things on faith.

## 0:25–1:00 — Prove it: the decoy drop (10 alerts → 5 real)

```bash
PYTHONPATH=patchproof python -m patchproof run patchproof/vulnbank/app.py --engine ast
```

Say: every alert gets a live exploit. Five confirm. Five are decoys —
marked `NOT CONFIRMED (likely false positive)`, no patch attempted, ever.
Expected console close: `5/5 confirmed issues fixed & verified`. That is
the noise funnel: raw alerts N → confirmed M → fixed K, and unconfirmed
alerts are dropped, not patched.

## 1:00–1:35 — The gate: variant block + BYPASSABLE rejection

Say: blocking the one demo payload is not a fix. The gate replays the
whole per-CWE payload corpus (comment tricks, tautologies, unions for
SQLi; metacharacter families for command injection; depth shapes for
traversal; tag families for XSS) against every patched copy — 85 payloads
blocked out of 85 across both fixtures — and any survivor rejects the
patch as `PATCH BYPASSABLE`. A patch that breaks a feature is likewise
rejected as `PATCH BREAKS APP`. Only `FIXED & VERIFIED` means both halves
proved: exploit blocked AND regressions green. Measured per-function patch
coverage on this run: mean 0.93 across the 8 patched functions.

## 1:35–2:10 — Second app: it is not a VulnBank trick

```bash
PYTHONPATH=patchproof python -m patchproof sarif patchproof/shopapi/app.py --engine ast --output /tmp/shop.sarif
```

Say: different stack (FastAPI, async handlers, JSON), different bug
classes — SQLi again plus unsafe deserialization (CWE-502) and a
hardcoded credential (CWE-798). Same templates, same gate:
`3 confirmed, 3 fixed & verified → GATE PASS`. The request shape comes
from the finding, never from hardcoded endpoints.

## 2:10–2:40 — CI: the machine-readable contract

```bash
PYTHONPATH=patchproof python -m patchproof sarif --check /tmp/shop.sarif
```

Say: `patchproof sarif` emits SARIF 2.1.0 (rule/CWE/severity/location +
patch status per finding) and exits nonzero unless everything confirmed
is fixed and verified. `.github/workflows/patchproof.yml` runs it on both
fixtures, uploads the SARIF log to code scanning plus the HTML report,
shape-checks both files, and then runs root `pytest` and
`secureai eval --once` (8/8 acceptance gates). A PR only merges when the
gate passes. (The workflow is declared here, not executed here.)

## 2:40–3:00 — Business close (one breath)

Say: the buyer is the team drowning in SAST noise — the wedge is a
drop-in CI gate that turns "10 alerts" into "5 proven fixes with
evidence". Open core (scanner + gate) with per-repo SaaS for the
dashboard, history, and policy packs. The moat is the evidence both ends:
a live exploit that kills false positives, and a variant-corpus gate
that kills bypasses. Details: [PATCHPROOF_BUSINESS.md](PATCHPROOF_BUSINESS.md).
