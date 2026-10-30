"use client";

import { ArrowRight, Check, Mail, ShieldCheck } from "lucide-react";
import { useState } from "react";

const DEMO_EMAIL = "security@agentshield.dev";

export function DemoForm() {
  const [status, setStatus] = useState<"idle" | "prepared">("idle");

  const submit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const name = String(data.get("name") ?? "").trim();
    const email = String(data.get("email") ?? "").trim();
    const company = String(data.get("company") ?? "").trim();
    const agents = String(data.get("agents") ?? "").trim();
    const message = String(data.get("message") ?? "").trim();

    const body = [
      `Name: ${name}`,
      `Work email: ${email}`,
      `Company: ${company}`,
      `Agents in production: ${agents}`,
      "",
      "What they are building:",
      message || "(not provided)",
    ].join("\n");

    const href = `mailto:${DEMO_EMAIL}?subject=${encodeURIComponent(
      `Demo request — ${company || name || "AgentShield"}`,
    )}&body=${encodeURIComponent(body)}`;

    window.location.href = href;
    setStatus("prepared");
  };

  if (status === "prepared") {
    return (
      <div className="demo-success" aria-live="polite">
        <span className="demo-success-icon">
          <Check className="h-7 w-7" strokeWidth={2} />
        </span>
        <p className="kicker justify-center">
          <span className="kicker-mark" /> Request prepared
        </p>
        <h3>One last step.</h3>
        <p>
          Your email client should open with the request filled in. Send that
          message and a member of the AgentShield team will reply within one
          business day to set up a tailored enforcement walkthrough.
        </p>
        <p>
          Nothing opened?{" "}
          <a className="text-link" href={`mailto:${DEMO_EMAIL}`}>
            <Mail className="h-3.5 w-3.5" /> Email {DEMO_EMAIL}
          </a>
        </p>
        <button
          type="button"
          className="text-link"
          onClick={() => setStatus("idle")}
        >
          Submit another request <ArrowRight className="h-3.5 w-3.5" />
        </button>
      </div>
    );
  }

  return (
    <form className="demo-form" onSubmit={submit} aria-label="Request a demo">
      <div className="demo-form-grid">
        <label>
          <span>Full name</span>
          <input name="name" type="text" autoComplete="name" placeholder="Ava Morgan" required />
        </label>
        <label>
          <span>Work email</span>
          <input
            name="email"
            type="email"
            autoComplete="email"
            placeholder="ava@company.com"
            required
          />
        </label>
        <label>
          <span>Company</span>
          <input name="company" type="text" autoComplete="organization" placeholder="Northstar" required />
        </label>
        <label>
          <span>Agents in production</span>
          <select name="agents" defaultValue="1–10" required>
            <option>0 — still exploring</option>
            <option>1–10</option>
            <option>11–50</option>
            <option>51–200</option>
            <option>200+</option>
          </select>
        </label>
      </div>
      <label className="demo-form-full">
        <span>What are you building?</span>
        <textarea
          name="message"
          rows={3}
          placeholder="We're shipping a customer-facing agent with access to billing and email…"
        />
      </label>
      <div className="demo-form-footer">
        <p>
          <ShieldCheck className="h-3.5 w-3.5" /> No spam. No sales sequences. Just a
          working session.
        </p>
        <button type="submit" className="btn btn-primary">
          Request a demo <ArrowRight className="h-4 w-4" />
        </button>
      </div>
    </form>
  );
}
