"use client";

import {
  AlertTriangle,
  ArrowUpRight,
  CheckCircle2,
  Cpu,
  Gauge,
  KeyRound,
  LockKeyhole,
  Network,
  RefreshCw,
  Scale,
  ServerCog,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Terminal,
} from "lucide-react";
import Link from "next/link";
import { useMemo } from "react";
import {
  formatNumber,
  formatTimestamp,
} from "@/lib/api/format";
import type {
  AuditResponse,
  EnforceResponse,
  EvidenceResponse,
  HealthResponse,
  PolicyResponse,
  ReadyResponse,
  RedteamScenariosResponse,
} from "@/lib/api/types";
import { useLiveData } from "@/lib/hooks/use-live-data";
import { cn } from "@/lib/utils";
import {
  Banner,
  Card,
  CardBody,
  CardHead,
  Dot,
  ErrorState,
  KeyValue,
  LiveMeta,
  PageHeader,
  StatCard,
  StatusBadge,
} from "@/components/workspace/ui";

const endpoints = [
  {
    method: "GET",
    path: "/health",
    auth: "public",
    purpose: "Liveness, detector names, whether API auth is required.",
  },
  {
    method: "GET",
    path: "/ready",
    auth: "public",
    purpose: "Readiness: policy loaded and at least one detector active.",
  },
  {
    method: "POST",
    path: "/v1/check",
    auth: "api key",
    purpose: "Policy decision point. Returns an advisory verdict and audits the call.",
  },
  {
    method: "GET",
    path: "/v1/audit",
    auth: "api key",
    purpose: "Recent decision records. Bounded to 500 entries.",
  },
  {
    method: "GET",
    path: "/v1/enforce",
    auth: "api key",
    purpose: "Current global enforcement switch.",
  },
  {
    method: "POST",
    path: "/v1/admin/enforce",
    auth: "admin key",
    purpose: "Flip the global enforcement switch. Audit-logged.",
  },
  {
    method: "POST",
    path: "/v1/admin/reset",
    auth: "admin key",
    purpose: "Re-ingest the packaged RAG corpus. Audit history retained.",
  },
  {
    method: "GET",
    path: "/v1/evidence",
    auth: "api key",
    purpose: "Health, enforcement, provenance mode and recent audit entries.",
  },
  {
    method: "GET",
    path: "/v1/metrics",
    auth: "api key",
    purpose: "Derived decision metrics and bucketed series.",
  },
  {
    method: "GET",
    path: "/v1/threats",
    auth: "api key",
    purpose: "Detector findings with inferred presentation labels.",
  },
  {
    method: "GET",
    path: "/v1/approvals",
    auth: "api key",
    purpose: "Pending queue, recent human decisions and capabilities.",
  },
  {
    method: "POST",
    path: "/v1/approvals/{call_id}",
    auth: "admin key",
    purpose: "Append a single-use, argument-hash-bound human decision.",
  },
  {
    method: "GET",
    path: "/v1/policy",
    auth: "api key",
    purpose: "Read-only policy YAML, defaults, tools, digest and stages.",
  },
  {
    method: "GET",
    path: "/v1/tools",
    auth: "api key",
    purpose: "Active policy tools joined with observed audit activity.",
  },
  {
    method: "GET",
    path: "/v1/agents",
    auth: "api key",
    purpose: "Agent/session groupings derived from audit metadata.",
  },
  {
    method: "GET",
    path: "/v1/corpus",
    auth: "api key",
    purpose: "Every retrieval record, tagged UNTRUSTED at ingest.",
  },
  {
    method: "GET",
    path: "/v1/redteam/scenarios",
    auth: "admin key",
    purpose: "Built-in attack scenarios for the isolated harness.",
  },
  {
    method: "GET",
    path: "/v1/redteam/history",
    auth: "admin key",
    purpose: "Dedicated red-team audit file, separate from the main trail.",
  },
  {
    method: "POST",
    path: "/v1/redteam/run",
    auth: "admin key",
    purpose: "Run one payload with enforcement ON and OFF in fresh runtimes.",
  },
  {
    method: "GET",
    path: "/v1/evidence/reports",
    auth: "api key",
    purpose: "Committed artifacts and live runtime evidence manifest.",
  },
] as const;

export function SettingsClient() {
  const health = useLiveData<HealthResponse>("/health", { intervalMs: 20_000 });
  const ready = useLiveData<ReadyResponse>("/ready", { intervalMs: 20_000 });
  const enforce = useLiveData<EnforceResponse>("/v1/enforce", { intervalMs: 20_000 });
  const policy = useLiveData<PolicyResponse>("/v1/policy", { intervalMs: 30_000 });
  const evidence = useLiveData<EvidenceResponse>("/v1/evidence?limit=1", {
    intervalMs: 30_000,
  });
  const readProbe = useLiveData<AuditResponse>("/v1/audit?limit=1", {
    intervalMs: 30_000,
  });
  const adminProbe = useLiveData<RedteamScenariosResponse>("/v1/redteam/scenarios", {
    intervalMs: 30_000,
  });

  const refreshing =
    health.isRefreshing ||
    ready.isRefreshing ||
    enforce.isRefreshing ||
    policy.isRefreshing ||
    evidence.isRefreshing ||
    readProbe.isRefreshing ||
    adminProbe.isRefreshing;

  const refreshAll = () => {
    void Promise.all([
      health.refresh(),
      ready.refresh(),
      enforce.refresh(),
      policy.refresh(),
      evidence.refresh(),
      readProbe.refresh(),
      adminProbe.refresh(),
    ]);
  };

  const detectors = useMemo(() => health.data?.detectors ?? [], [health.data]);
  const llmDetectors = useMemo(
    () =>
      detectors.filter((detector) =>
        /llm|gemini|openai|anthropic|model|gpt|claude/i.test(detector),
      ),
    [detectors],
  );

  const readStatus = readProbe.data
    ? "authorized"
    : readProbe.failure?.status === 401
      ? "rejected"
      : readProbe.failure
        ? "unreachable"
        : "checking";

  const adminStatus = adminProbe.data
    ? "authorized"
    : adminProbe.failure?.status === 401 || adminProbe.failure?.status === 403
      ? "rejected"
      : adminProbe.failure
        ? "unreachable"
        : "checking";

  const gatewayDown = health.failure && !health.data;

  return (
    <div className="ws-stack">
      <PageHeader
        eyebrow="Gateway & configuration"
        title={
          <>
            The runtime, <em>as reported.</em>
          </>
        }
        description="Live health, readiness, authorization probes, detector inventory, provenance mode and policy integrity. No secret value is ever sent to the browser; the Next.js proxy attaches credentials server-side."
        actions={
          <button
            type="button"
            className="ws-btn is-sm"
            onClick={refreshAll}
            disabled={refreshing}
          >
            <RefreshCw className={cn("h-3.5 w-3.5", refreshing && "animate-spin")} />
            {refreshing ? "Refreshing" : "Refresh"}
          </button>
        }
      />

      {gatewayDown ? (
        <ErrorState failure={health.failure!} onRetry={refreshAll} />
      ) : null}

      <div className="ws-grid ws-grid-4">
        <StatCard
          label="Gateway"
          value={
            health.data ? (
              <span className="flex items-baseline gap-2">
                {health.data.status.toUpperCase()}
                <small>{ready.data?.ready ? "ready" : "not ready"}</small>
              </span>
            ) : (
              "—"
            )
          }
          meta={health.data ? "GET /health · GET /ready" : "Waiting for gateway"}
          icon={ServerCog}
        />
        <StatCard
          label="API access"
          value={readStatus}
          meta={
            health.data
              ? health.data.auth_required
                ? "API key required by gateway"
                : "Open dev gateway"
              : "Probing /v1/audit"
          }
          icon={KeyRound}
          tone={readStatus === "authorized" ? "lime" : undefined}
        />
        <StatCard
          label="Admin access"
          value={adminStatus}
          meta="Probed with GET /v1/redteam/scenarios"
          icon={LockKeyhole}
          tone={adminStatus === "authorized" ? "purple" : undefined}
        />
        <StatCard
          label="Enforcement"
          value={enforce.data ? (enforce.data.enforced ? "ON" : "OFF") : "—"}
          meta="Global switch · admin-key gated"
          icon={ShieldCheck}
          tone={enforce.data?.enforced ? "lime" : undefined}
        />
      </div>

      <div id="health" className="ws-grid ws-grid-main ws-anchor">
        <Card>
          <CardHead
            title="Runtime status"
            subtitle="Values read live from the gateway"
            icon={Gauge}
            actions={
              health.lastUpdated ? (
                <LiveMeta
                  lastUpdated={health.lastUpdated}
                  isRefreshing={refreshing}
                  isStale={health.isStale}
                  intervalLabel="20s"
                />
              ) : null
            }
          />
          <CardBody>
            <div className="ws-stack">
              <KeyValue
                items={[
                  {
                    label: "Health",
                    value: health.data ? (
                      <span className="ws-row">
                        <Dot tone="ok" /> {health.data.status}
                      </span>
                    ) : health.failure ? (
                      <span className="ws-row">
                        <Dot tone="error" /> {health.failure.message}
                      </span>
                    ) : (
                      "Checking…"
                    ),
                  },
                  {
                    label: "Readiness",
                    value: ready.data?.ready ? (
                      <span className="ws-row">
                        <Dot tone="ok" /> policy loaded, detector active
                      </span>
                    ) : ready.failure ? (
                      <span className="ws-row">
                        <Dot tone="error" /> {ready.failure.message}
                      </span>
                    ) : (
                      "Checking…"
                    ),
                  },
                  {
                    label: "Auth mode",
                    value: health.data
                      ? health.data.auth_required
                        ? "API key required"
                        : "Open dev gateway (no API key)"
                      : "—",
                  },
                  {
                    label: "Read probe",
                    value: (
                      <span className="flex flex-wrap items-center gap-2">
                        <StatusBadge
                          tone={
                            readStatus === "authorized"
                              ? "ok"
                              : readStatus === "checking"
                                ? "neutral"
                                : "error"
                          }
                        >
                          {readStatus}
                        </StatusBadge>
                        {readProbe.failure ? (
                          <span className="ws-hint">{readProbe.failure.message}</span>
                        ) : null}
                      </span>
                    ),
                  },
                  {
                    label: "Admin probe",
                    value: (
                      <span className="flex flex-wrap items-center gap-2">
                        <StatusBadge
                          tone={
                            adminStatus === "authorized"
                              ? "ok"
                              : adminStatus === "checking"
                                ? "neutral"
                                : "error"
                          }
                        >
                          {adminStatus}
                        </StatusBadge>
                        {adminProbe.failure ? (
                          <span className="ws-hint">{adminProbe.failure.message}</span>
                        ) : null}
                      </span>
                    ),
                  },
                  {
                    label: "Gateway URL",
                    value: "Configured server-side · not exposed to browser",
                  },
                  {
                    label: "Last updated",
                    value: formatTimestamp(health.lastUpdated),
                  },
                ]}
              />
              {adminStatus === "rejected" ? (
                <div className="ws-banner is-warn">
                  <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
                  <div>
                    The admin-gated probe was rejected. Approvals, enforcement changes,
                    corpus reset and the Red Team Lab will return 401/403 until{" "}
                    <code className="ws-mono">AGENTSHIELD_ADMIN_KEY</code> is configured
                    correctly on the Next.js server.
                  </div>
                </div>
              ) : null}
              {readStatus === "rejected" ? (
                <div className="ws-banner is-error">
                  <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
                  <div>
                    The API-key-gated probe was rejected. The proxy cannot read gateway
                    data. Check <code className="ws-mono">AGENTSHIELD_API_KEY</code> in
                    the Next.js server environment.
                  </div>
                </div>
              ) : null}
            </div>
          </CardBody>
        </Card>

        <div className="ws-detail">
          <Card>
            <CardHead
              title="Detectors & LLM"
              subtitle="No separate LLM status endpoint exists"
              icon={Cpu}
            />
            <CardBody>
              <div className="ws-stack">
                <KeyValue
                  items={[
                    {
                      label: "Detectors",
                      value: detectors.length ? detectors.join(", ") : "none reported",
                      mono: true,
                    },
                    {
                      label: "Count",
                      value: formatNumber(detectors.length),
                    },
                    {
                      label: "LLM detector",
                      value: llmDetectors.length ? (
                        <StatusBadge tone="ok">{llmDetectors.join(", ")}</StatusBadge>
                      ) : (
                        <StatusBadge tone="neutral">not reported</StatusBadge>
                      ),
                    },
                  ]}
                />
                {llmDetectors.length ? (
                  <div className="ws-banner">
                    <Sparkles className="mt-0.5 h-4 w-4 shrink-0" />
                    <div>
                      An LLM-named detector is active. Its provider, model and
                      credential state are not exposed by /health; this console does
                      not invent them.
                    </div>
                  </div>
                ) : (
                  <div className="ws-banner is-warn">
                    <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                    <div>
                      No LLM detector is reported by /health. The active detector list
                      is the only detector status the gateway exposes. There is no LLM
                      credential or provider endpoint for this console to query.
                    </div>
                  </div>
                )}
                <div className="ws-rule-note">
                  <LockKeyhole className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                  <span>
                    LLM credentials, if any, remain server-side. The browser bundle never
                    receives them.
                  </span>
                </div>
              </div>
            </CardBody>
          </Card>

          <Card>
            <CardHead
              title="Policy & provenance"
              subtitle="Integrity and trust-root state"
              icon={Scale}
            />
            <CardBody>
              <div className="ws-stack">
                <KeyValue
                  items={[
                    {
                      label: "Policy",
                      value: policy.data
                        ? `${policy.data.name} · v${policy.data.version}`
                        : "—",
                      mono: true,
                    },
                    {
                      label: "Digest",
                      value: policy.data?.digest ?? "unavailable",
                      mono: true,
                    },
                    {
                      label: "Pinned",
                      value: policy.data ? (
                        <StatusBadge tone={policy.data.digest_pinned ? "ok" : "warn"}>
                          {policy.data.digest_pinned ? "yes" : "no"}
                        </StatusBadge>
                      ) : (
                        "—"
                      ),
                    },
                    {
                      label: "Integrity",
                      value:
                        policy.data?.integrity_verified === true ? (
                          <StatusBadge tone="ok">verified</StatusBadge>
                        ) : policy.data?.digest_pinned ? (
                          <StatusBadge tone="error">mismatch</StatusBadge>
                        ) : (
                          <StatusBadge tone="warn">pin not set</StatusBadge>
                        ),
                    },
                    {
                      label: "Provenance",
                      value: evidence.data ? (
                        <StatusBadge
                          tone={evidence.data.provenance_dev_mode ? "warn" : "ok"}
                        >
                          {evidence.data.provenance_dev_mode ? "dev mode" : "HMAC enforced"}
                        </StatusBadge>
                      ) : (
                        "—"
                      ),
                    },
                  ]}
                />
                {evidence.data?.provenance_dev_mode ? (
                  <div className="ws-banner is-warn">
                    <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
                    <div>
                      Self-asserted sources are honored in dev mode. Set{" "}
                      <code className="ws-mono">AGENTSHIELD_HARNESS_SECRET</code> before
                      exposing the gateway.
                    </div>
                  </div>
                ) : null}
              </div>
            </CardBody>
          </Card>
        </div>
      </div>

      <Card id="configuration" className="ws-anchor">
        <CardHead
          title="Configuration actions"
          subtitle="Destructive actions live on their dedicated pages with confirmation"
          icon={Network}
        />
        <CardBody>
          <div className="ws-grid ws-grid-3">
            <Link
              href="/workspace"
              className="ws-tool-card transition-colors hover:border-[#bdb9b1]"
            >
              <div className="ws-tool-head">
                <span className="ws-tool-name">Enforcement switch</span>
                <ArrowUpRight className="h-4 w-4" />
              </div>
              <p className="ws-hint">
                Turn global enforcement ON or OFF from the Overview. The action is
                admin-key gated and audit-logged.
              </p>
              <StatusBadge tone={enforce.data?.enforced ? "ok" : "warn"}>
                currently {enforce.data ? (enforce.data.enforced ? "ON" : "OFF") : "unknown"}
              </StatusBadge>
            </Link>
            <Link
              href="/workspace/corpus"
              className="ws-tool-card transition-colors hover:border-[#bdb9b1]"
            >
              <div className="ws-tool-head">
                <span className="ws-tool-name">Corpus re-ingest</span>
                <ArrowUpRight className="h-4 w-4" />
              </div>
              <p className="ws-hint">
                Reload the packaged RAG corpus from the RAG Corpus page. Audit history is
                retained.
              </p>
              <StatusBadge tone="neutral">confirmed action</StatusBadge>
            </Link>
            <Link
              href="/workspace/policy"
              className="ws-tool-card transition-colors hover:border-[#bdb9b1]"
            >
              <div className="ws-tool-head">
                <span className="ws-tool-name">Policy changes</span>
                <ArrowUpRight className="h-4 w-4" />
              </div>
              <p className="ws-hint">
                Policy is read-only in this build. There is no publish endpoint; change
                the file through your reviewed deployment process.
              </p>
              <StatusBadge tone="warn">no write API</StatusBadge>
            </Link>
          </div>
        </CardBody>
      </Card>

      <Card>
        <CardHead
          title="Endpoint map"
          subtitle="Every route used by this workspace · credentials attached server-side"
          icon={Terminal}
        />
        <CardBody flush>
          <div className="ws-table-wrap">
            <table className="ws-table">
              <thead>
                <tr>
                  <th>Method</th>
                  <th>Path</th>
                  <th>Auth</th>
                  <th>Purpose</th>
                </tr>
              </thead>
              <tbody>
                {endpoints.map((endpoint) => (
                  <tr key={`${endpoint.method}-${endpoint.path}`}>
                    <td className="font-mono text-[10px] font-semibold">
                      {endpoint.method}
                    </td>
                    <td className="font-mono text-[10px]">{endpoint.path}</td>
                    <td>
                      <StatusBadge
                        tone={
                          endpoint.auth === "public"
                            ? "neutral"
                            : endpoint.auth === "admin key"
                              ? "warn"
                              : "ok"
                        }
                      >
                        {endpoint.auth}
                      </StatusBadge>
                    </td>
                    <td className="text-[10.5px] text-[#4d4a45]">{endpoint.purpose}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardBody>
      </Card>

      <Banner tone="purple" icon={CheckCircle2}>
        <strong>No secrets in the browser.</strong> The gateway URL and keys are read by
        the Next.js proxy from server-side environment variables. This page shows only
        presence/authorization outcomes. It never displays key values.
      </Banner>
    </div>
  );
}
