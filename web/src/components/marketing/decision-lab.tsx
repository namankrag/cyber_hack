"use client";

import {
  ArrowRight,
  Check,
  FileText,
  Fingerprint,
  Loader2,
  Mail,
  RotateCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
} from "lucide-react";
import { useEffect, useState } from "react";
import { Reveal } from "@/components/marketing/reveal";

type Decision = "ALLOW" | "DENY" | "REQUIRE_APPROVAL";
type Phase = "idle" | "running" | "done";

type Scenario = {
  id: string;
  title: string;
  short: string;
  summary: string;
  agent: string;
  tool: string;
  source: string;
  risk: string;
  decision: Decision;
  reasons: string[];
  icon: typeof FileText;
  audit: string;
};

const scenarios: Scenario[] = [
  {
    id: "poisoned-invoice",
    title: "The poisoned invoice",
    short: "Hidden instructions try to move money.",
    summary:
      "A finance copilot opens a vendor invoice, follows a hidden instruction, and attempts an outbound wire.",
    agent: "finance-copilot",
    tool: "payments.transfer",
    source: "untrusted_document",
    risk: "Critical",
    decision: "DENY",
    reasons: [
      "Provenance resolved to invoice_Q3.pdf · untrusted",
      "payments.* requires a verified human source",
      "Instruction override detected at 0.94 confidence",
    ],
    icon: FileText,
    audit: "ASH-8F2A-C19D",
  },
  {
    id: "verified-read",
    title: "The routine lookup",
    short: "A signed-in user asks for an account.",
    summary:
      "A support agent looks up a customer record after a verified session requests it. Narrow scope, low risk.",
    agent: "support-copilot",
    tool: "crm.accounts.read",
    source: "verified_session",
    risk: "Low",
    decision: "ALLOW",
    reasons: [
      "Provenance signed by user session · trusted",
      "Tool scope is read-only and within policy",
      "No deny rules fired; least privilege preserved",
    ],
    icon: Search,
    audit: "ASH-4E71-A02B",
  },
  {
    id: "vendor-send",
    title: "The external send",
    short: "A new vendor asks to email a deck.",
    summary:
      "An ops agent prepares an external email from a third-party request. The action is valid, but needs a human.",
    agent: "ops-copilot",
    tool: "gmail.send_external",
    source: "third_party_email",
    risk: "Elevated",
    decision: "REQUIRE_APPROVAL",
    reasons: [
      "Provenance resolved to an external email thread",
      "External sends require a named approver",
      "Request routed to #revops · expires in 15 min",
    ],
    icon: Mail,
    audit: "ASH-2B90-D71E",
  },
];

const decisionCopy: Record<Decision, { label: string; detail: string }> = {
  ALLOW: {
    label: "ALLOW",
    detail: "The action runs — inside policy, on the record.",
  },
  DENY: {
    label: "DENY",
    detail: "The tool call never reaches the system.",
  },
  REQUIRE_APPROVAL: {
    label: "REQUIRE APPROVAL",
    detail: "Execution pauses until a human says yes.",
  },
};

export function DecisionLab() {
  const [activeIndex, setActiveIndex] = useState(0);
  const [phase, setPhase] = useState<Phase>("done");
  const active = scenarios[activeIndex];

  useEffect(() => {
    if (phase !== "running") return;
    const timer = window.setTimeout(() => setPhase("done"), 1250);
    return () => window.clearTimeout(timer);
  }, [phase, activeIndex]);

  const run = () => setPhase("running");
  const select = (index: number) => {
    setActiveIndex(index);
    setPhase("running");
  };

  const Icon = active.icon;
  const running = phase === "running";
  const evaluated = phase === "done";

  return (
    <section id="try-it" className="lab-section" data-nav-section>
      <div className="wrap lab-grid">
        <Reveal className="lab-copy">
          <p className="kicker">
            <span className="kicker-mark" /> Try a decision
          </p>
          <h2 className="display display-lg">
            See what gets
            <br />
            <span className="serif-accent">through.</span>
          </h2>
          <p className="lede">
            Three agent actions. Three different verdicts. Pick a scenario and watch
            the boundary do its job before a single tool runs.
          </p>

          <div className="scenario-list" role="tablist" aria-label="Example scenarios">
            {scenarios.map((scenario, index) => {
              const ScenarioIcon = scenario.icon;
              return (
                <button
                  key={scenario.id}
                  type="button"
                  role="tab"
                  aria-selected={activeIndex === index}
                  className={`scenario-button ${activeIndex === index ? "is-active" : ""}`}
                  onClick={() => select(index)}
                >
                  <span className="scenario-icon">
                    <ScenarioIcon className="h-[18px] w-[18px]" strokeWidth={1.8} />
                  </span>
                  <span className="scenario-text">
                    <strong>{scenario.title}</strong>
                    <span>{scenario.short}</span>
                  </span>
                  <span className={`scenario-decision decision-${scenario.decision.toLowerCase()}`}>
                    {scenario.decision === "REQUIRE_APPROVAL" ? "HOLD" : scenario.decision}
                  </span>
                </button>
              );
            })}
          </div>

          <p className="lab-footnote">
            <Sparkles className="h-3.5 w-3.5" />
            Sandbox data. Real engine semantics: most-restrictive-wins, fail-closed.
          </p>
        </Reveal>

        <Reveal className="lab-stage" delay={100}>
          <div className="lab-shell">
            <div className="lab-shell-top">
              <div className="flex items-center gap-2.5">
                <span className="lab-mark">
                  <ShieldCheck className="h-4 w-4" strokeWidth={2} />
                </span>
                <span className="text-[12px] font-semibold tracking-[-0.01em] text-[#171717]">
                  AgentShield
                </span>
                <span className="mono-label hidden text-[#8b8a86] sm:inline">/ PLAYGROUND</span>
              </div>
              <span className="live-badge">
                <span className="live-dot" /> SANDBOX
              </span>
            </div>

            <div className="lab-toolbar">
              <div>
                <span className="mono-label text-[#8b8a86]">EVENT</span>
                <p className="mt-0.5 font-mono text-[11.5px] font-medium text-[#171717]">
                  {active.audit}
                </p>
              </div>
              <span className="lab-toolbar-divider" />
              <div>
                <span className="mono-label text-[#8b8a86]">SOURCE</span>
                <p className="mt-0.5 font-mono text-[11.5px] font-medium text-[#5b4b7b]">
                  {active.source}
                </p>
              </div>
              <span className="lab-toolbar-divider" />
              <div>
                <span className="mono-label text-[#8b8a86]">RISK</span>
                <p className="mt-0.5 font-mono text-[11.5px] font-medium text-[#171717]">
                  {active.risk}
                </p>
              </div>
              <span className="lab-toolbar-spacer" />
              <span className={`lab-state ${running ? "is-running" : ""}`}>
                {running ? (
                  <>
                    <Loader2 className="h-3 w-3 animate-spin" /> Evaluating
                  </>
                ) : (
                  <>
                    <Check className="h-3 w-3" /> Complete
                  </>
                )}
              </span>
            </div>

            <div className="lab-scroll">
              <div className="lab-event-card">
                <div className="lab-event-icon">
                  <Icon className="h-5 w-5" strokeWidth={1.8} />
                </div>
                <div className="min-w-0 flex-1">
                  <span className="mono-label text-[#8b8a86]">AGENT REQUESTS</span>
                  <p className="mt-1 truncate font-mono text-[14px] font-medium text-[#171717]">
                    {active.tool}
                  </p>
                  <p className="mt-0.5 truncate text-[11px] text-[#777777]">{active.agent}</p>
                </div>
                <span className={`risk-chip risk-${active.risk.toLowerCase()}`}>{active.risk}</span>
              </div>

              <div className="lab-pipeline" aria-live="polite">
                {[
                  { label: "Provenance", detail: active.source, icon: Fingerprint },
                  { label: "Threat scan", detail: "Instruction intent", icon: ShieldAlert },
                  { label: "Policy engine", detail: "Most-restrictive-wins", icon: ShieldCheck },
                ].map((step, index) => {
                  const StepIcon = step.icon;
                  return (
                    <div className="lab-pipeline-step" key={step.label}>
                      <span className="pipeline-index">0{index + 1}</span>
                      <span className="pipeline-icon">
                        <StepIcon className="h-3.5 w-3.5" strokeWidth={1.8} />
                      </span>
                      <span className="min-w-0 flex-1">
                        <strong>{step.label}</strong>
                        <span className="truncate">{step.detail}</span>
                      </span>
                      <span className={`pipeline-status ${evaluated ? "is-done" : ""}`}>
                        {running ? (
                          <Loader2 className="h-3.5 w-3.5 animate-spin" />
                        ) : evaluated ? (
                          <Check className="h-3.5 w-3.5" />
                        ) : (
                          <span className="h-1.5 w-1.5 rounded-full bg-current" />
                        )}
                      </span>
                      {index < 2 && <span className="pipeline-connector" aria-hidden="true" />}
                    </div>
                  );
                })}
              </div>

              <div
                className={`verdict-card verdict-${active.decision.toLowerCase()} ${
                  running ? "is-thinking" : ""
                }`}
              >
                <div className="verdict-main">
                  <span className="verdict-label">DECISION</span>
                  <strong>{running ? "···" : decisionCopy[active.decision].label}</strong>
                  <span className="verdict-detail">{decisionCopy[active.decision].detail}</span>
                </div>
                <div className="verdict-stamp" aria-hidden="true">
                  {active.decision === "ALLOW" ? (
                    <Check className="h-8 w-8" strokeWidth={1.7} />
                  ) : active.decision === "DENY" ? (
                    <ShieldAlert className="h-8 w-8" strokeWidth={1.6} />
                  ) : (
                    <span className="font-mono text-xl font-semibold">?</span>
                  )}
                </div>
              </div>

              <div className="reason-box">
                <span className="mono-label text-[#8b8a86]">WHY</span>
                <ul>
                  {active.reasons.map((reason, index) => (
                    <li key={reason} className={running ? "is-waiting" : ""}>
                      <span className="reason-index">{index + 1}</span>
                      <span>{reason}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>

            <div className="lab-shell-bottom">
              <span className="hidden items-center gap-1.5 text-[10.5px] text-[#8b8a86] sm:flex">
                <Fingerprint className="h-3.5 w-3.5" /> Signed and written to audit
              </span>
              <button type="button" className="lab-run" onClick={run} disabled={running}>
                {running ? (
                  <>
                    <Loader2 className="h-3.5 w-3.5 animate-spin" /> Evaluating
                  </>
                ) : (
                  <>
                    <RotateCw className="h-3.5 w-3.5" /> Re-run evaluation
                  </>
                )}
              </button>
            </div>
          </div>

          <div className="lab-float-card" aria-hidden="true">
            <span className="mono-label text-[#8b8a86]">BOUNDARY</span>
            <strong>Enforced</strong>
            <span>before execution</span>
          </div>
          <div className="lab-float-pill" aria-hidden="true">
            <ArrowRight className="h-3.5 w-3.5" /> zero trust by default
          </div>
        </Reveal>
      </div>
    </section>
  );
}
