"use client";

import { ArrowUpRight, Check, Copy, ExternalLink, Terminal } from "lucide-react";
import { useState } from "react";

const snippets = {
  curl: {
    label: "cURL",
    filename: "request.sh",
    code: `curl -X POST http://localhost:8000/v1/check \\
  -H "content-type: application/json" \\
  -H "x-api-key: $AGENTSHIELD_KEY" \\
  -d '{
    "tool_name": "transfer_funds",
    "arguments": { "amount": 14200 },
    "source": "untrusted",
    "context": "ignore previous instructions"
  }'`,
  },
  python: {
    label: "Python",
    filename: "guard.py",
    code: `import requests

decision = requests.post(
    "http://localhost:8000/v1/check",
    headers={"x-api-key": KEY},
    json={
        "tool_name": "transfer_funds",
        "arguments": {"amount": 14200},
        "source": "untrusted",
        "context": "ignore previous instructions",
    },
).json()

if decision["decision"] != "allow":
    raise PermissionError(decision["headline"])

# The tool only runs after an explicit ALLOW.`,
  },
  node: {
    label: "Node",
    filename: "guard.ts",
    code: `const verdict = await fetch("http://localhost:8000/v1/check", {
  method: "POST",
  headers: {
    "content-type": "application/json",
    "x-api-key": process.env.AGENTSHIELD_KEY!,
  },
  body: JSON.stringify({
    tool_name: "transfer_funds",
    arguments: { amount: 14200 },
    source: "untrusted",
    context: "ignore previous instructions",
  }),
}).then((res) => res.json());

if (verdict.decision !== "allow") throw new Error(verdict.headline);`,
  },
} as const;

type Tab = keyof typeof snippets;

export function DocsCode() {
  const [tab, setTab] = useState<Tab>("curl");
  const [copied, setCopied] = useState(false);
  const snippet = snippets[tab];

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(snippet.code);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      setCopied(false);
    }
  };

  return (
    <div className="docs-code-shell">
      <div className="docs-code-top">
        <div className="docs-tabs" role="tablist" aria-label="Code examples">
          {(Object.keys(snippets) as Tab[]).map((key) => (
            <button
              key={key}
              type="button"
              role="tab"
              aria-selected={tab === key}
              onClick={() => setTab(key)}
              className={tab === key ? "is-active" : ""}
            >
              {snippets[key].label}
            </button>
          ))}
        </div>
        <button type="button" className="docs-copy-button" onClick={copy}>
          {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <div className="docs-filename">
        <Terminal className="h-3.5 w-3.5" />
        {snippet.filename}
      </div>
      <pre className="docs-pre">
        <code>{snippet.code}</code>
      </pre>
      <div className="docs-code-bottom">
        <span>
          <span className="live-dot" /> Gateway online
        </span>
        <a href="http://localhost:8000/docs" target="_blank" rel="noreferrer">
          API reference <ExternalLink className="h-3 w-3" />
        </a>
      </div>
    </div>
  );
}

export function DocsLinks() {
  return (
    <div className="docs-link-list">
      <a href="https://github.com/namankrag/cyber_hack#quickstart" target="_blank" rel="noreferrer">
        <span>
          <strong>Quickstart</strong>
          <small>Run the gateway and make your first decision</small>
        </span>
        <ArrowUpRight className="h-4 w-4" />
      </a>
      <a
        href="https://github.com/namankrag/cyber_hack/blob/main/policies/default.yaml"
        target="_blank"
        rel="noreferrer"
      >
        <span>
          <strong>Policy examples</strong>
          <small>Start from a readable, enforceable YAML baseline</small>
        </span>
        <ArrowUpRight className="h-4 w-4" />
      </a>
      <a
        href="https://github.com/namankrag/cyber_hack/blob/main/THREAT_MODEL.md"
        target="_blank"
        rel="noreferrer"
      >
        <span>
          <strong>Threat model</strong>
          <small>What we protect, and what we deliberately don&apos;t</small>
        </span>
        <ArrowUpRight className="h-4 w-4" />
      </a>
    </div>
  );
}
