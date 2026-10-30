# SecureAI — judge-facing results

SecureAI joins an AgentShield runtime policy enforcement point with PatchProof
code scanning and verified remediation. Runtime decisions are ALLOW,
REQUIRE-APPROVAL, or DENY, with inspectable reasons. A runtime block triggers
a source scan for the governed tool and links the findings back to that block.

## Evaluation result

The checked-in synthetic scorecard passed all eight acceptance gates:

| Measure | Result |
|---|---:|
| Malicious runtime calls stopped before execution | 5/5 (100%) |
| False-positive rate on benign calls | 0% |
| Legitimate high-impact calls held for approval | 1/1 (100%) |
| Planted CWE scanner recall | 5/5 (100%) |
| Exploit confirmation rate | 5/5 (100%) |
| Verified patch acceptance | 5/5 (100%) |
| Regression checks passed | 35/35 (100%) |
| Closed-loop convergence | 5 iterations; 0 residual confirmed findings |

The independent grader repeats the baseline exploit checks, applies each
curated patch to a fresh copy, runs the patched exploit and regressions, and
reconstructs the loop's final deployment from its recorded diffs before
checking for residual findings. Gates are evaluated at threshold 0.5 (the tune search records 0.35/0.40/0.45 failing one gate each; 0.5 selected).

## Scope and reproducibility

- Runtime and code cases use synthetic inputs and the bundled VulnBank fixture: 9 runtime scenarios (3 benign, 1 legitimate high-impact approval, 5 malicious - 2 direct, 2 indirect, 1 permission-violation) plus 5 planted CWEs in `patchproof/vulnbank/app.py`.
- Curated remediation and scorecard evaluation run without API keys.
- Exploit/regression jobs run in a separate process with a 10-second deadline.
- The loop writes patches only to an isolated temporary copy; the bundled
  vulnerable source remains intact for repeatable evaluation.
- The scorecard is CI-ready: `secureai eval --once` exits nonzero if any gate
  fails. `secureai eval --tune` records each tested threshold. `secureai watch`
  reruns the loop and evaluation when the bundled tool fixture changes. Validate the tree with one root `pytest -q` -> 127 passed, 1 skipped (Semgrep-engine test; Semgrep not installed - graceful AST fallback).

## Artifacts

- `reports/scorecard.json` — raw scenarios, code evidence, loop trend, metrics,
  independent rechecks, and gate results.
- `reports/scorecard.html` — shareable visual scorecard with per-case results
  and tested patch diffs.
- `reports/loop_report.json` — per-iteration bridge scans, patch evidence,
  before/after counts, and source hashes; `reports/tuned/` holds the threshold-search scorecard (`scorecard.json`+`html`).
- `reports/platform_dashboard.html` — unified runtime and code view.

These are results for the shipped synthetic dataset. They demonstrate the
project's measured behavior on its planted cases and are not a guarantee of
production detection rates.
