# SecureAI — 90-second demo

All steps use the bundled synthetic fixtures. No API keys or external services
are needed for the core demo.

## 0:00–0:20 — runtime enforcement and bridge

Run:

```bash
secureai platform --engine ast --report reports/platform_dashboard.html
```

Show the unified dashboard or console output. Point out the allowed public
search, blocked injected customer-data call, and legitimate email held for
approval. The blocked call automatically opens a linked code scan for the
governed tool implementation.

## 0:20–0:45 — closed remediation loop

Run:

```bash
secureai loop --max-iters 8 --report reports/loop_report.json
```

Show the confirmed-finding count falling from five to zero. Each iteration
applies one minimal patch to an isolated VulnBank copy, verifies that exploit
is blocked and regressions remain green, re-attacks the deployed copy, and
rescans it. An unverified patch stops for human review.

## 0:45–1:10 — evaluation gates

Run:

```bash
secureai eval --once --out-dir reports
```

Show the `8/8 gates` result and the generated `reports/scorecard.html`. The
scorecard includes per-scenario decisions and reasons, code locations and
patch evidence, regression outcomes, and the loop trend. The independent
grader rechecks the code findings and the reconstructed final loop copy.

## 1:10–1:30 — close

Highlight the scorecard: five of five planted CWEs found, exploit-confirmed,
and fixed; 35 of 35 regression checks pass; the loop converges in five
iterations with zero residual confirmed vulnerabilities. Benign false
positives are zero in this synthetic set, and the legitimate high-impact
email is held for approval.

Finish by noting the scope: the demo proves the configured behavior against
the bundled practice app and labeled synthetic scenarios. It does not claim
that a heuristic detector catches every real-world prompt injection.
