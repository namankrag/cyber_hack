# PatchProof — business note

## Buyer

Engineering and AppSec teams whose SAST pipeline produces more alerts
than anyone will ever triage. The economic pain is not "we miss bugs" —
it is "we pay senior engineers to dismiss false positives and we still
do not trust the patches". The demo-measured funnel (16 raw alerts
across two apps → 8 confirmed → 8 fixed, 85/85 variant payloads blocked)
is the sales artifact: it converts scanner output into a short list of
proven fixes with evidence attached.

## Wedge

A drop-in CI gate, not a platform migration. `patchproof sarif` emits
SARIF 2.1.0 and exits nonzero unless every confirmed finding is
`FIXED & VERIFIED`; the reusable workflow
(`.github/workflows/patchproof.yml`) uploads the SARIF log to code
scanning and the HTML report as an artifact. Adoption is one workflow
file and one merge rule. No agent rewrite, no new language, no cloud
dependency — the AST engine and the sandbox run offline.

## Pricing (open core + SaaS)

- **Open core (free):** scanner (AST engine), exploit/regression
  templates, curated patches, the verification gate, SARIF + HTML
  reports, the CI workflow. Everything needed to reproduce the demo.
- **Paid SaaS (per repo / per seat):** hosted gate history and trend
  dashboards, PR comments with the exploit evidence inline, policy
  packs (per-CWE severity and minimality thresholds), Semgrep-managed
  rules at scale, SSO/audit retention for compliance reviews.
- **Services (optional):** custom fixture onboarding — model a
  customer's own service the way VulnBank/ShopAPI model Flask/FastAPI,
  register its CWE templates, and the same gate proves its fixes.

## Moat

Most tools stop at "scanner found X, here is a patch". PatchProof shows
evidence on both ends: a live exploit proving the bug is real (killing
false-positive noise) and a patch proven to kill that exploit plus its
whole variant corpus without breaking the app (killing bypasses and
regressions). Each layer compounds — the decoy set, the variant corpora,
the per-function coverage, the curated patches — and each is cheap to
extend but expensive to replicate with the same rigor. The independent
grader (which recomputes precision, block rate, and coverage from raw
evidence instead of trusting the pipeline's flags) is the trust anchor
an enterprise buyer can audit.

## Scaling

- **Engines:** AST today, Semgrep rules bundled, `both/auto` union
  already supported; CodeQL-class engines slot into the same gate.
- **Coverage:** more CWE classes and more fixtures per the manifest
  pattern (allowlisted dir + sha256 pins); the second app (ShopAPI)
  already proves the templates are not fixture-specific.
- **Throughput:** sandboxed jobs are batchable per finding and per
  variant; the gate parallelizes per issue with no shared state.
- **Enterprise:** Postgres/Redis-backed audit and approvals already
  exist on the SecureAI side; the same backends serve gate history
  and retention for the SaaS tier.
