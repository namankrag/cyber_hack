"use client";

import {
  ArrowRight,
  Check,
  CircleCheck,
  Fingerprint,
  LockKeyhole,
  ScanSearch,
  Scale,
  ShieldCheck,
  Terminal,
} from "lucide-react";
import { useState } from "react";
import { Reveal } from "@/components/marketing/reveal";

const steps = [
  {
    number: "01",
    label: "Inspect",
    title: "The call is intercepted.",
    body: "Every tool request is captured at the boundary — tool name, arguments, calling agent, and the context around it.",
    icon: ScanSearch,
    meta: "Request captured",
  },
  {
    number: "02",
    label: "Verify",
    title: "Provenance is resolved.",
    body: "AgentShield traces where the instruction came from, outside the model. A poisoned document cannot claim to be a trusted user.",
    icon: Fingerprint,
    meta: "Trust established",
  },
  {
    number: "03",
    label: "Evaluate",
    title: "Policy gets the final word.",
    body: "Detectors score intent. The policy engine composes every matching rule, most-restrictive-wins. Unknown means escalate, never allow.",
    icon: Scale,
    meta: "Rules composed",
  },
  {
    number: "04",
    label: "Enforce",
    title: "One decision. Fully logged.",
    body: "ALLOW runs. DENY stops cold. REQUIRE_APPROVAL pauses for a human. Every outcome is signed and appended to the audit trail.",
    icon: ShieldCheck,
    meta: "Decision sealed",
  },
];

function StepVisual({ index }: { index: number }) {
  if (index === 0) {
    return (
      <div className="hiw-visual hiw-inspect">
        <div className="hiw-visual-head">
          <span className="hiw-window-dots">
            <i />
            <i />
            <i />
          </span>
          <span>intercept / request</span>
          <span className="hiw-live-chip">
            <span /> LIVE
          </span>
        </div>
        <pre>
          <code>
            <span className="code-dim">{"{"}</span>
            {"\n  "}
            <span className="code-key">&quot;agent&quot;</span>
            <span className="code-dim">: </span>
            <span className="code-string">&quot;finance-copilot&quot;</span>
            <span className="code-dim">,</span>
            {"\n  "}
            <span className="code-key">&quot;tool&quot;</span>
            <span className="code-dim">: </span>
            <span className="code-string">&quot;transfer_funds&quot;</span>
            <span className="code-dim">,</span>
            {"\n  "}
            <span className="code-key">&quot;amount&quot;</span>
            <span className="code-dim">: </span>
            <span className="code-number">14200</span>
            <span className="code-dim">,</span>
            {"\n  "}
            <span className="code-key">&quot;source&quot;</span>
            <span className="code-dim">: </span>
            <span className="code-warn">&quot;invoice_Q3.pdf&quot;</span>
            {"\n"}
            <span className="code-dim">{"}"}</span>
          </code>
        </pre>
        <div className="hiw-caption">
          <Terminal className="h-3.5 w-3.5" /> Captured in-process or over the MCP gateway
        </div>
      </div>
    );
  }

  if (index === 1) {
    return (
      <div className="hiw-visual hiw-verify">
        <div className="hiw-visual-head">
          <span>provenance / chain</span>
          <span className="hiw-live-chip is-purple">VERIFIED</span>
        </div>
        <div className="trust-path">
          <div className="trust-node is-source">
            <span className="trust-node-icon">
              <Fingerprint className="h-4 w-4" />
            </span>
            <span>
              <strong>user.request</strong>
              <small>signed session · verified</small>
            </span>
            <span className="trust-badge trust-good">TRUSTED</span>
          </div>
          <span className="trust-line">
            <span />
          </span>
          <div className="trust-node">
            <span className="trust-node-icon">
              <span className="trust-dot" />
            </span>
            <span>
              <strong>invoice_Q3.pdf</strong>
              <small>ingested document · third party</small>
            </span>
            <span className="trust-badge trust-bad">UNTRUSTED</span>
          </div>
          <span className="trust-line">
            <span />
          </span>
          <div className="trust-node is-action">
            <span className="trust-node-icon">
              <ArrowRight className="h-4 w-4" />
            </span>
            <span>
              <strong>transfer_funds</strong>
              <small>requested by finance-copilot</small>
            </span>
            <span className="trust-badge trust-bad">HIGH RISK</span>
          </div>
        </div>
        <div className="hiw-caption">
          <LockKeyhole className="h-3.5 w-3.5" /> Source claims are established outside the model
        </div>
      </div>
    );
  }

  if (index === 2) {
    return (
      <div className="hiw-visual hiw-evaluate">
        <div className="hiw-visual-head">
          <span>policy / compose</span>
          <span className="hiw-live-chip is-purple">3 RULES</span>
        </div>
        <pre className="policy-code">
          <code>
            <span className="code-dim">- id: </span>
            <span className="code-key">verified-user-read</span>
            {"\n  "}
            <span className="code-key">decision:</span>
            <span className="code-string"> allow</span>
            {"\n  "}
            <span className="code-key">when:</span>
            <span className="code-dim"> source == verified</span>
            {"\n\n"}
            <span className="code-dim">- id: </span>
            <span className="code-key">no-untrusted-finance</span>
            {"\n  "}
            <span className="code-key">decision:</span>
            <span className="code-warn"> deny</span>
            {"\n  "}
            <span className="code-key">when:</span>
            <span className="code-dim"> source == untrusted</span>
            {"\n  "}
            <span className="code-key">tool:</span>
            <span className="code-string"> payments.*</span>
          </code>
        </pre>
        <div className="policy-result-row">
          <span>
            <Check className="h-3.5 w-3.5" /> no-untrusted-finance
          </span>
          <span className="mono-label">MATCH</span>
        </div>
        <div className="policy-result-row is-muted">
          <span>
            <Check className="h-3.5 w-3.5" /> verified-user-read
          </span>
          <span className="mono-label">NO MATCH</span>
        </div>
        <div className="hiw-caption">
          <Scale className="h-3.5 w-3.5" /> Most-restrictive-wins. Adding rules cannot widen access.
        </div>
      </div>
    );
  }

  return (
    <div className="hiw-visual hiw-enforce">
      <div className="hiw-visual-head">
        <span>verdict / signed</span>
        <span className="hiw-live-chip">SEALED</span>
      </div>
      <div className="enforce-card">
        <div className="enforce-icon">
          <ShieldCheck className="h-8 w-8" strokeWidth={1.6} />
        </div>
        <div>
          <span className="mono-label text-[#8b8a86]">DECISION</span>
          <strong className="enforce-verdict">DENY</strong>
          <p>transfer_funds blocked</p>
        </div>
      </div>
      <div className="enforce-meta">
        <span>
          <CircleCheck className="h-3.5 w-3.5" /> Tool never executed
        </span>
        <span>
          <Fingerprint className="h-3.5 w-3.5" /> Audit call_86c3…
        </span>
      </div>
      <div className="enforce-audit">
        <span className="mono-label text-[#8b8a86]">AUDIT ENTRY</span>
        <p>
          2026-10-31T14:32:08Z · deny · finance-copilot · transfer_funds
        </p>
        <span className="audit-hash">sha256: 9c1e…7b2a</span>
      </div>
      <div className="hiw-caption">
        <ShieldCheck className="h-3.5 w-3.5" /> Signed, append-only, and inspectable
      </div>
    </div>
  );
}

export function HowItWorks() {
  const [active, setActive] = useState(0);
  const step = steps[active];
  const Icon = step.icon;

  return (
    <section id="how-it-works" className="hiw-section">
      <div className="hiw-glow" aria-hidden="true" />
      <div className="wrap">
        <Reveal className="hiw-heading">
          <p className="kicker kicker-light">
            <span className="kicker-mark" /> How it works
          </p>
          <div className="hiw-heading-row">
            <h2 className="display display-lg text-[#F8F7F4]">
              Four checks.
              <br />
              <span className="text-[#C9F45A]">One unskippable</span>
              <br />
              decision.
            </h2>
            <p className="hiw-lede">
              AgentShield sits between your agent and everything it can touch. The model
              can be persuaded. The boundary cannot.
            </p>
          </div>
        </Reveal>

        <div className="hiw-layout">
          <div className="hiw-steps" role="tablist" aria-label="How AgentShield works">
            {steps.map((item, index) => {
              const StepIcon = item.icon;
              return (
                <button
                  key={item.number}
                  type="button"
                  role="tab"
                  aria-selected={active === index}
                  onClick={() => setActive(index)}
                  className={`hiw-step ${active === index ? "is-active" : ""}`}
                >
                  <span className="hiw-step-number">{item.number}</span>
                  <span className="hiw-step-icon">
                    <StepIcon className="h-4 w-4" strokeWidth={1.8} />
                  </span>
                  <span className="hiw-step-copy">
                    <span className="hiw-step-label">{item.label}</span>
                    <strong>{item.title}</strong>
                    <span>{item.body}</span>
                  </span>
                  <span className="hiw-step-arrow">
                    <ArrowRight className="h-4 w-4" />
                  </span>
                </button>
              );
            })}
          </div>

          <div className="hiw-stage">
            <div className="hiw-stage-top">
              <span className="hiw-stage-icon">
                <Icon className="h-4 w-4" strokeWidth={1.9} />
              </span>
              <span className="font-mono text-[length:var(--as-fs-label)] font-medium uppercase tracking-[0.08em] text-[#F8F7F4]/70">
                {step.meta}
              </span>
              <span className="hiw-step-counter">
                STEP {step.number} / 04
              </span>
            </div>
            <div key={active} className="hiw-visual-wrap">
              <StepVisual index={active} />
            </div>
            <div className="hiw-stage-bottom">
              <div className="hiw-progress" aria-hidden="true">
                {steps.map((_, index) => (
                  <span key={index} className={index <= active ? "is-filled" : ""} />
                ))}
              </div>
              <button
                type="button"
                className="hiw-next"
                onClick={() => setActive((current) => (current + 1) % steps.length)}
              >
                Next step <ArrowRight className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
