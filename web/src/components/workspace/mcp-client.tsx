"use client";

import { Fingerprint, KeyRound, Loader2, Network, Play, ShieldCheck, TriangleAlert } from "lucide-react";
import Link from "next/link";
import { useCallback, useState } from "react";
import { apiPost } from "@/lib/api/client";
import { toApiFailure, type ApiFailure } from "@/lib/api/errors";
import type { McpDemoResponse, TrustDemoResponse } from "@/lib/api/types";
import { cn } from "@/lib/utils";
import {
  Banner,
  Card,
  CardBody,
  CardHead,
  DecisionBadge,
  EmptyState,
  ErrorState,
  PageHeader,
} from "@/components/workspace/ui";

const BEFORE = `{
  "mcpServers": {
    "tools": {
      "command": "python",
      "args": ["your_mcp_server.py"]
    }
  }
}`;

const AFTER = `{
  "mcpServers": {
    "tools": {
      "command": "python",
      "args": ["-m", "agentshield.gateway.mcp_gateway"],
      "env": {
        "AGENTSHIELD_UPSTREAM_CMD": "python your_mcp_server.py"
      }
    }
  }
}`;

function useRun<T>(path: string) {
  const [data, setData] = useState<T | null>(null);
  const [failure, setFailure] = useState<ApiFailure | null>(null);
  const [running, setRunning] = useState(false);
  const run = useCallback(async () => {
    setRunning(true);
    setFailure(null);
    try {
      setData(await apiPost<T>(path, {}, undefined, 30_000));
    } catch (error) {
      setFailure(toApiFailure(error));
    } finally {
      setRunning(false);
    }
  }, [path]);
  return { data, failure, running, run };
}

export function McpClient() {
  const mcp = useRun<McpDemoResponse>("/v1/mcp/demo");
  const trust = useRun<TrustDemoResponse>("/v1/trust/demo");

  return (
    <div className="ws-stack">
      <PageHeader
        eyebrow="MCP Gateway"
        title={
          <>
            Enforcement at the <em>protocol layer.</em>
          </>
        }
        description="AgentShield runs as an MCP server in front of your real tools. Every tools/call passes the same detector and policy engine before the upstream tool sees it, so adopting it is a one-line change in the MCP client config."
      />

      <Card>
        <CardHead title="Adopt it: one line in your MCP client config" icon={Network} subtitle="Point the client at the gateway; the gateway fronts your server over stdio" />
        <CardBody>
          <div className="ws-mcp-config">
            <div>
              <p className="ws-label">Before</p>
              <pre>{BEFORE}</pre>
            </div>
            <div>
              <p className="ws-label">After</p>
              <pre>{AFTER}</pre>
            </div>
          </div>
          <p className="ws-hint">
            Entry point: <code>python -m agentshield.gateway.mcp_gateway</code> (stdio). Without{" "}
            <code>AGENTSHIELD_UPSTREAM_CMD</code> it serves its built-in demo tools.
          </p>
        </CardBody>
      </Card>

      <Card>
        <CardHead
          title="Live MCP session"
          icon={Play}
          subtitle="A real MCP client (official SDK) connects, lists tools and calls them. Scenarios are fixed on the server."
          actions={
            <button type="button" className="ws-btn is-sm" onClick={() => void mcp.run()} disabled={mcp.running}>
              {mcp.running ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />}
              {mcp.data ? "Run again" : "Run live MCP session"}
            </button>
          }
        />
        <CardBody>
          {mcp.failure ? <ErrorState failure={mcp.failure} onRetry={() => void mcp.run()} compact /> : null}
          {!mcp.data && !mcp.failure ? (
            <EmptyState
              icon={Network}
              title="No session run yet"
              description="Press Run: you'll see initialize, tools/list and each tools/call with what AgentShield decided."
            />
          ) : null}
          {mcp.data ? <McpTranscript data={mcp.data} /> : null}
        </CardBody>
      </Card>

      <Card>
        <CardHead
          title="Can the agent fake its way in?"
          icon={KeyRound}
          subtitle="Trust comes from a token the harness signs, not from what the call claims"
          actions={
            <button type="button" className="ws-btn is-sm" onClick={() => void trust.run()} disabled={trust.running}>
              {trust.running ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />}
              {trust.data ? "Run again" : "Try it"}
            </button>
          }
        />
        <CardBody>
          {trust.failure ? (
            trust.failure.status === 409 ? (
              <Banner tone="warn" icon={TriangleAlert}>
                <strong>Dev mode: this comparison would be misleading.</strong> {trust.failure.message}
              </Banner>
            ) : (
              <ErrorState failure={trust.failure} onRetry={() => void trust.run()} compact />
            )
          ) : null}
          {!trust.data && !trust.failure ? (
            <EmptyState
              icon={Fingerprint}
              title="Three attempts at the customer database"
              description="One claims to be the user with no token, one carries a genuine harness-signed token, and one replays that same token."
            />
          ) : null}
          {trust.data ? (
            <div className="ws-trust-grid">
              {trust.data.checks.map((check) => (
                <div key={check.label} className={cn("ws-trust-row", `is-${check.decision}`)}>
                  <p className="ws-trust-label">{check.label}</p>
                  <dl>
                    <dt>Claimed</dt>
                    <dd className="font-mono">{check.asserted_source}</dd>
                    <dt>Token</dt>
                    <dd>{check.token}</dd>
                    <dt>Treated as</dt>
                    <dd className="font-mono">{check.resolved_source}</dd>
                  </dl>
                  <DecisionBadge decision={check.decision} />
                  <p className="ws-hint">{check.resolve_reason}</p>
                  <Link href={`/workspace/audit?call=${encodeURIComponent(check.call_id)}`} className="ws-doclab-audit">
                    <Fingerprint className="h-3.5 w-3.5" /> {check.call_id}
                  </Link>
                </div>
              ))}
            </div>
          ) : null}
        </CardBody>
      </Card>
    </div>
  );
}

function McpTranscript({ data }: { data: McpDemoResponse }) {
  return (
    <div className="ws-stack">
      {data.provenance_mode === "dev" ? (
        <Banner tone="warn" icon={TriangleAlert}>
          <strong>Harness secret not set: claimed sources are honoured (dev mode).</strong> Set
          AGENTSHIELD_HARNESS_SECRET and restart the gateway to require signed tokens.
        </Banner>
      ) : null}
      <ol className="ws-mcp-log">
        <li>
          <code>initialize</code>
          <span className="ws-hint">
            transport {data.transport} · {data.duration_ms} ms for the whole session
          </span>
        </li>
        <li>
          <code>tools/list</code>
          <span className="ws-mcp-tools">
            {data.tools.map((tool) => (
              <span key={tool} className="ws-doclab-signal">
                {tool}
              </span>
            ))}
          </span>
        </li>
        {data.calls.map((call, index) => (
          <li key={`${call.tool}-${index}`} className={cn("ws-mcp-call", call.outcome === "blocked" ? "is-blocked" : "is-executed")}>
            <div className="ws-doclab-decision-head">
              <code>tools/call</code>
              <code className="ws-doclab-tool">{call.tool}</code>
              <span className="ws-doclab-spacer" />
              <span className={cn("ws-badge", call.outcome === "blocked" ? "is-deny" : "is-allow")}>
                {call.outcome === "blocked" ? "Blocked" : "Executed"}
              </span>
              {call.decision ? <DecisionBadge decision={call.decision} /> : null}
            </div>
            <p className="ws-doclab-narration">{call.label}</p>
            <p className="ws-doclab-args">
              <span>source</span> {call.asserted_source}{" "}
              <span>token</span> {call.token_attached ? "harness-signed" : "none"}{" "}
              <span>args</span> {JSON.stringify(call.arguments_without_tag)}
            </p>
            {call.outcome === "blocked" ? (
              <McpReasons text={call.text} />
            ) : (
              <p className="ws-hint">
                <ShieldCheck className="inline h-3.5 w-3.5" /> The upstream tool ran and returned: {call.text.slice(0, 160)}
              </p>
            )}
          </li>
        ))}
      </ol>
    </div>
  );
}

/**
 * Blocked results list reasons as "- [rule] detail" lines (see mcp_gateway._deny).
 * The text carries no per-reason decision, so none is shown.
 */
function McpReasons({ text }: { text: string }) {
  const reasons = text
    .split("\n")
    .map((line) => /^\s*-\s*\[([^\]]+)\]\s*(.*)$/.exec(line))
    .filter((m): m is RegExpExecArray => m !== null);
  if (!reasons.length) return <pre className="ws-mcp-raw">{text}</pre>;
  return (
    <ul className="ws-mcp-reasons">
      {reasons.map((m, index) => (
        <li key={`${m[1]}-${index}`}>
          <code>{m[1]}</code> {m[2]}
        </li>
      ))}
    </ul>
  );
}
