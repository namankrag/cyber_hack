# SecureAI — 3-minute pitch (problem → proof → scale + business)

## 0:00–0:30 — Problem

AI agents get hijacked by any doc they read: instructions hidden in
content they were asked to process turn a helpful agent into an
exfiltration tool (OWASP LLM01), and over-broad tool powers let it act
on them (OWASP LLM06). Two-line version: AgentShield is the code
boundary between agent and tools — every call gets allow, deny, or
approval with proof — so even a compromised model cannot leak.

## 0:30–1:10 — OFF leaks, ON blocks (with reason)

The same poisoned `send_email` call, twice. Enforcement OFF: ALLOW —
without the boundary, the model obeys the document. Enforcement ON:
DENY, with the quoted rule (`injection_detected` + `untrusted_source`)
and severity attached. Run `examples/rag_demo` beats 1–3 live: legit
search ALLOW, poison read DENY, legitimate email HELD then
human-approved. Every verdict carries ordered rule ids plus quoted
evidence into the append-only audit log.

## 1:10–1:50 — The approval click + benchmark numbers

The legitimate high-impact email is held, a human clicks approve, done —
containment without killing the workflow. Numbers from the frozen
84-case benchmark: OFF 100% attack success → ON 4.3%, benign false
positives 0.0%, high-impact approval correctness 100%, decision latency
p50 under 1ms. Full suite: 268 passed, 1 skipped; semgrep 0 findings
over 238 rules. Three honest misses are disclosed in BENCHMARK.md —
hold is containment, not a verdict.

## 1:50–2:20 — PatchProof: the same rigor for code

Scanners flag 10 things on one small app; PatchProof exploits each one
(5 confirm, 5 decoys dropped unpatched), blocks all 85 variant payloads
across two apps, and accepts a patch only when the exploit is blocked
AND regressions stay green: 8 confirmed → 8 fixed and verified. The CI
gate takes SARIF 2.1.0 and fails the PR unless everything confirmed is
fixed. Details: docs/PATCHPROOF_DEMO_3MIN.md.

## 2:20–3:00 — Scale + business

Stateless engine, replicas behind your edge balancer, Redis/Postgres
backends for approvals and audit. Buyer: fintech, banks, BPOs — audited
customer-data workflows, with Hindi/Kannada/Tamil/Telugu UPI lures
already in the benchmark for the India angle. Wedge: a drop-in proxy
plus a one-file CI gate. Open core with per-agent SaaS; compliance
logging maps to OWASP LLM01/LLM06, India's DPDP Act and RBI audit
expectations, and EU AI Act record-keeping. What we did not solve —
a per-process token replay cache (multi-worker needs a shared backend),
stdio-only upstream MCP proxying (no HTTP/SSE yet), TLS/secrets
operator-owned — is in THREAT_MODEL.md, not hidden.
