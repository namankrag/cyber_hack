# Two-line pitch (use verbatim)

AI agents get hijacked by any doc they read. AgentShield is the code boundary
between agent and tools — every call gets allow, deny, or approval with proof —
so even a compromised model cannot leak.

# Q&A (30-second answers, all demoable)

**False positives?** They hold for approval, never deny. Watch the legit email
beat: HELD, human approves, done. Benign corpus docs all score zero (tested).

**Bypasses?** Only by skipping the PEP — and the OFF-vs-ON beat proves the
boundary is what stops the leak. Same poisoned call: OFF leaks, ON denies.

**Multilingual?** Hindi/Kannada UPI lures are flagged (tested); paraphrase can
still miss, and then the policy contains it — untrusted callers never touch
high-sensitivity tools, and trusted callers with detected injections are denied.

**What did you NOT solve?** Replayable provenance tokens (documented roadmap),
no upstream MCP proxy yet, TLS/secrets/rotation are operator-owned. See
THREAT_MODEL.md — we disclose non-goals instead of hiding them.

**Why not just a better prompt?** System prompts are suggestions; boundaries
are code. The policy engine, not the model, has the last word — mapped to
OWASP LLM01 (prompt injection) + LLM06 (excessive agency).
