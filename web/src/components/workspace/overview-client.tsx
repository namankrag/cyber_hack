"use client";

import {
  Activity,
  ArrowRight,
  BadgeCheck,
  Bot,
  Clock3,
  Database,
  Gauge,
  LockKeyhole,
  RefreshCw,
  ScanSearch,
  Scale,
  ScrollText,
  Send,
  ShieldAlert,
  ShieldCheck,
  UserCheck,
  Users,
} from "lucide-react";
import Link from "next/link";
import { useMemo, useState } from "react";
import { apiPost } from "@/lib/api/client";
import { toApiFailure, type ApiFailure } from "@/lib/api/errors";
import {
  decisionClass,
  formatDelta,
  formatNumber,
  formatRelative,
  formatTimestamp,
} from "@/lib/api/format";
import type {
  AdminEnforceResponse,
  AgentsResponse,
  ApprovalsResponse,
  AuditResponse,
  EnforceResponse,
  HealthResponse,
  MetricsResponse,
  ReadyResponse,
  ThreatsResponse,
} from "@/lib/api/types";
import { useLiveData } from "@/lib/hooks/use-live-data";
import { cn } from "@/lib/utils";
import { ConfirmDialog } from "@/components/workspace/confirm-dialog";
import {
  Banner,
  Bars,
  Card,
  CardBody,
  CardHead,
  DecisionBadge,
  Distribution,
  Dot,
  ErrorState,
  InlineLoading,
  KeyValue,
  LiveMeta,
  LoadingState,
  NavyFeaturePanel,
  PageHeader,
  SecurityPipeline,
  SourceBadge,
  Sparkline,
  StatCard,
  StaleBanner,
  StatusBadge,
  SuccessNote,
  TrendChart,
} from "@/components/workspace/ui";
import {
  timeWindowLabels,
  useTimeWindow,
} from "@/components/workspace/time-window";

export function OverviewClient() {
  const { windowKey } = useTimeWindow();
  const [confirmEnforce, setConfirmEnforce] = useState(false);
  const [togglePending, setTogglePending] = useState(false);
  const [toggleFailure, setToggleFailure] = useState<ApiFailure | null>(null);
  const [toggleSuccess, setToggleSuccess] = useState<string | null>(null);

  const health = useLiveData<HealthResponse>("/health", { intervalMs: 15_000 });
  const ready = useLiveData<ReadyResponse>("/ready", { intervalMs: 15_000 });
  const enforce = useLiveData<EnforceResponse>("/v1/enforce", { intervalMs: 15_000 });
  const metrics = useLiveData<MetricsResponse>(
    `/v1/metrics?window=${windowKey}&limit=500`,
    { intervalMs: 15_000 },
  );
  const threats = useLiveData<ThreatsResponse>("/v1/threats?limit=500", {
    intervalMs: 20_000,
  });
  const approvals = useLiveData<ApprovalsResponse>("/v1/approvals?limit=500", {
    intervalMs: 20_000,
  });
  const agents = useLiveData<AgentsResponse>("/v1/agents?limit=500", {
    intervalMs: 20_000,
  });
  const audit = useLiveData<AuditResponse>("/v1/audit?limit=12", {
    intervalMs: 15_000,
  });

  const refreshing =
    metrics.isRefreshing ||
    threats.isRefreshing ||
    approvals.isRefreshing ||
    agents.isRefreshing ||
    audit.isRefreshing ||
    health.isRefreshing;

  const refreshAll = () => {
    void Promise.all([
      health.refresh(),
      ready.refresh(),
      enforce.refresh(),
      metrics.refresh(),
      threats.refresh(),
      approvals.refresh(),
      agents.refresh(),
      audit.refresh(),
    ]);
  };

  const totals = metrics.data?.totals;
  const distribution = metrics.data?.decision_distribution ?? [];
  const allowCount = distribution.find((row) => row.decision === "allow")?.count ?? 0;
  const holdCount =
    distribution.find((row) => row.decision === "require_approval")?.count ?? 0;
  const denyCount = distribution.find((row) => row.decision === "deny")?.count ?? 0;

  const pending = approvals.data?.summary.pending ?? totals?.pending_approvals ?? 0;
  const topSessions = useMemo(
    () => (agents.data?.sessions ?? []).slice(0, 4),
    [agents.data],
  );
  const topTools = useMemo(
    () => (metrics.data?.top_tools ?? []).slice(0, 6),
    [metrics.data],
  );
  const recentThreats = useMemo(
    () => (threats.data?.events ?? []).slice(0, 4),
    [threats.data],
  );
  const recentAudit = useMemo(() => (audit.data?.entries ?? []).slice(0, 8), [audit.data]);

  const series = useMemo(() => metrics.data?.series ?? [], [metrics.data]);
  const allowSeries = useMemo(() => series.map((point) => point.allow), [series]);
  const denySeries = useMemo(() => series.map((point) => point.deny), [series]);
  const holdSeries = useMemo(
    () => series.map((point) => point.require_approval),
    [series],
  );
  const totalSeries = useMemo(() => series.map((point) => point.total), [series]);

  const evaluated = totals?.evaluated ?? 0;
  const allowRate = evaluated > 0 ? ((totals?.allowed ?? 0) / evaluated) * 100 : null;
  const denyRate = evaluated > 0 ? ((totals?.blocked ?? 0) / evaluated) * 100 : null;
  const holdRate = evaluated > 0 ? ((totals?.held ?? 0) / evaluated) * 100 : null;

  const gatewayDown = health.failure && !health.data;
  const globalStale = metrics.failure && metrics.data;

  const currentEnforced = enforce.data?.enforced ?? false;
  const gatewayLive = Boolean(health.data && !health.failure);

  const pipelineTone = gatewayLive
    ? currentEnforced
      ? "ok"
      : "warn"
    : health.failure
      ? "error"
      : "idle";

  const applyEnforcement = async () => {
    setTogglePending(true);
    setToggleFailure(null);
    setToggleSuccess(null);
    try {
      const result = await apiPost<AdminEnforceResponse>("/v1/admin/enforce", {
        enabled: !currentEnforced,
      });
      setToggleSuccess(
        result.enforced
          ? "Global enforcement is now ON. New calls are enforced at the boundary."
          : "Global enforcement is now OFF. Calls are still evaluated and audited, and the would-be verdict is recorded.",
      );
      setConfirmEnforce(false);
      window.dispatchEvent(new Event("agentshield:enforce-changed"));
      await Promise.all([enforce.refresh(), metrics.refresh(), audit.refresh()]);
    } catch (error) {
      setToggleFailure(toApiFailure(error));
    } finally {
      setTogglePending(false);
    }
  };

  return (
    <div className="ws-stack">
      <PageHeader
        eyebrow="Operational overview"
        title={
          <>
            The boundary, <em>live.</em>
          </>
        }
        description="A real-time read of the AgentShield gateway: enforcement state, decision volume, threat signals, pending human decisions and the most recent audit records. Every number comes from the running backend."
        actions={
          <>
            <Link href="/workspace/analytics" className="ws-btn is-sm is-ghost">
              Analytics <ArrowRight className="h-3.5 w-3.5" />
            </Link>
            <button
              type="button"
              className="ws-btn is-sm"
              onClick={refreshAll}
              disabled={refreshing}
            >
              <RefreshCw className={cn("h-3.5 w-3.5", refreshing && "animate-spin")} />
              {refreshing ? "Refreshing" : "Refresh"}
            </button>
          </>
        }
      />

      {gatewayDown ? (
        <ErrorState failure={health.failure!} onRetry={refreshAll} />
      ) : null}
      {globalStale ? (
        <StaleBanner
          failure={metrics.failure!}
          lastUpdated={metrics.lastUpdated}
          onRetry={refreshAll}
        />
      ) : null}
      {toggleFailure ? <ErrorState failure={toggleFailure} compact /> : null}
      {toggleSuccess ? <SuccessNote>{toggleSuccess}</SuccessNote> : null}

      <Card className="ws-pipeline-card">
        <CardHead
          title="Security pipeline"
          subtitle="Every call moves through the same boundary before a tool can run"
          icon={ShieldCheck}
          actions={
            <span className="ws-count-pill">
              <Dot tone={gatewayLive ? (currentEnforced ? "ok" : "warn") : "neutral"} />
              {gatewayLive
                ? currentEnforced
                  ? "enforced"
                  : "observe only"
                : "gateway offline"}
            </span>
          }
        />
        <CardBody tight>
          <SecurityPipeline
            nodes={[
              {
                key: "ingest",
                label: "Gateway",
                detail: gatewayLive
                  ? `${health.data?.detectors.length ?? 0} detector${health.data?.detectors.length === 1 ? "" : "s"} active`
                  : "Waiting for /health",
                icon: Send,
                tone: gatewayLive ? "ok" : health.failure ? "error" : "idle",
              },
              {
                key: "detect",
                label: "Detect",
                detail: threats.data
                  ? `${formatNumber(threats.data.total)} findings retained`
                  : "Reading detector output",
                icon: ScanSearch,
                tone: threats.data ? "ok" : "idle",
              },
              {
                key: "policy",
                label: "Policy",
                detail: ready.data?.ready ? "policy loaded" : "readiness unknown",
                icon: Scale,
                tone: ready.data?.ready ? "ok" : ready.failure ? "error" : "idle",
              },
              {
                key: "decide",
                label: "Decide",
                detail: metrics.data
                  ? `${formatNumber(evaluated)} evaluated · ${formatNumber(denyCount)} denied`
                  : "Reading metrics",
                icon: ShieldCheck,
                tone: pipelineTone,
              },
              {
                key: "audit",
                label: "Audit",
                detail: audit.data
                  ? `${formatNumber(audit.data.entries.length)} recent records`
                  : "Reading audit trail",
                icon: ScrollText,
                tone: audit.data ? "ok" : "idle",
              },
            ]}
          />
        </CardBody>
      </Card>

      <div className="ws-grid ws-grid-4 ws-metric-grid">
        <StatCard
          label="Calls evaluated"
          value={metrics.data ? formatNumber(totals?.evaluated) : <InlineLoading label="Reading" />}
          meta={
            metrics.data ? (
              <>
                <Clock3 className="h-3 w-3" /> {timeWindowLabels[windowKey]} ·{" "}
                {formatDelta(metrics.data.deltas.evaluated)}
              </>
            ) : (
              "Waiting for gateway"
            )
          }
          icon={Activity}
          tone="cream"
          visual={<Sparkline values={totalSeries} tone="navy" />}
        />
        <StatCard
          label="Allowed"
          value={metrics.data ? formatNumber(totals?.allowed) : "—"}
          meta={
            metrics.data
              ? `${allowRate === null ? "—" : allowRate.toFixed(1)}% · explicit policy allow`
              : "Waiting for gateway"
          }
          icon={ShieldCheck}
          tone="lime"
          visual={<Sparkline values={allowSeries} tone="lime" />}
        />
        <StatCard
          label="Denied"
          value={metrics.data ? formatNumber(totals?.blocked) : "—"}
          meta={
            metrics.data
              ? `${denyRate === null ? "—" : denyRate.toFixed(1)}% · never reached the tool`
              : "Waiting for gateway"
          }
          icon={ShieldAlert}
          tone="peach"
          visual={<Sparkline values={denySeries} tone="peach" />}
        />
        <StatCard
          label="Held for approval"
          value={metrics.data ? formatNumber(totals?.held) : "—"}
          meta={
            metrics.data ? (
              <>
                <UserCheck className="h-3 w-3" />{" "}
                {holdRate === null ? "—" : holdRate.toFixed(1)}% ·{" "}
                {formatNumber(pending)} pending now
              </>
            ) : (
              "Waiting for gateway"
            )
          }
          icon={UserCheck}
          tone="purple"
          visual={<Sparkline values={holdSeries} tone="purple" />}
        />
      </div>

      <div className="ws-signal-strip">
        <Link href="/workspace/threats" className="ws-signal-tile">
          <span className="ws-signal-tile-icon is-peach">
            <ShieldAlert className="h-4 w-4" />
          </span>
          <span className="ws-signal-tile-copy">
            <strong>{threats.data ? formatNumber(threats.data.total) : "—"}</strong>
            <span>
              threat signals
              {threats.data
                ? ` · ${threats.data.severity.high} high · ${threats.data.severity.medium} medium`
                : ""}
            </span>
          </span>
          <ArrowRight className="h-3.5 w-3.5" />
        </Link>
        <Link href="/workspace/approvals" className="ws-signal-tile">
          <span className="ws-signal-tile-icon is-purple">
            <UserCheck className="h-4 w-4" />
          </span>
          <span className="ws-signal-tile-copy">
            <strong>{approvals.data ? formatNumber(pending) : "—"}</strong>
            <span>
              pending approvals
              {approvals.data
                ? ` · ${approvals.data.summary.approved} approved · ${approvals.data.summary.rejected} rejected`
                : ""}
            </span>
          </span>
          <ArrowRight className="h-3.5 w-3.5" />
        </Link>
        <Link href="/workspace/agents" className="ws-signal-tile">
          <span className="ws-signal-tile-icon is-lime">
            <Users className="h-4 w-4" />
          </span>
          <span className="ws-signal-tile-copy">
            <strong>{agents.data ? formatNumber(agents.data.count) : "—"}</strong>
            <span>
              agent sessions
              {agents.data ? ` · ${agents.data.sessions.length} projected` : ""}
            </span>
          </span>
          <ArrowRight className="h-3.5 w-3.5" />
        </Link>
        <Link href="/workspace/settings#health" className="ws-signal-tile">
          <span className="ws-signal-tile-icon is-navy">
            <Gauge className="h-4 w-4" />
          </span>
          <span className="ws-signal-tile-copy">
            <strong>
              {health.data
                ? health.data.status.toUpperCase()
                : health.failure
                  ? "OFFLINE"
                  : "…"}
            </strong>
            <span>
              gateway
              {health.data
                ? ` · ${ready.data?.ready ? "ready" : "not ready"} · ${health.data.auth_required ? "auth required" : "open dev mode"}`
                : ""}
            </span>
          </span>
          <ArrowRight className="h-3.5 w-3.5" />
        </Link>
      </div>

      <div className="ws-grid ws-grid-main">
        <Card>
          <CardHead
            title="Decision volume"
            subtitle={`${timeWindowLabels[windowKey]} window · ${metrics.data?.sample.events_in_window ?? 0} events read from the audit trail`}
            icon={Activity}
            actions={
              metrics.lastUpdated ? (
                <LiveMeta
                  lastUpdated={metrics.lastUpdated}
                  isRefreshing={metrics.isRefreshing}
                  isStale={metrics.isStale}
                />
              ) : null
            }
          />
          <CardBody>
            {metrics.isLoading ? (
              <LoadingState rows={2} />
            ) : metrics.failure && !metrics.data ? (
              <ErrorState failure={metrics.failure} onRetry={metrics.refresh} compact />
            ) : metrics.data ? (
              <div className="ws-stack">
                <Distribution allow={allowCount} hold={holdCount} deny={denyCount} />
                <div className="ws-divider" />
                <div>
                  <div className="ws-between mb-1">
                    <span className="ws-label">Volume by bucket</span>
                    <span className="ws-hint">
                      {metrics.data.series.length} buckets · {timeWindowLabels[windowKey]}
                    </span>
                  </div>
                  <TrendChart series={metrics.data.series} />
                </div>
                <div className="ws-banner">
                  <LockKeyhole className="mt-0.5 h-4 w-4 shrink-0" />
                  <div>
                    <strong>Data window:</strong> {timeWindowLabels[windowKey]} ·{" "}
                    {formatNumber(metrics.data.sample.entries_read)} audit entries read
                    (limit {metrics.data.sample.limit})
                    {metrics.data.sample.truncated
                      ? " · sample limit reached; older retained entries are outside this view"
                      : ""}
                    . {metrics.data.notes.durations}
                  </div>
                </div>
              </div>
            ) : null}
          </CardBody>
        </Card>

        <NavyFeaturePanel className="ws-enforcement-panel">
          <div className="ws-navy-head">
            <span className="ws-navy-eyebrow">Enforcement</span>
            <StatusBadge tone={currentEnforced ? "lime" : "warn"}>
              {enforce.data ? (currentEnforced ? "ON" : "OFF") : "UNKNOWN"}
            </StatusBadge>
          </div>

          <div className="ws-navy-hero">
            <span className="ws-navy-hero-icon">
              <Gauge className="h-5 w-5" />
            </span>
            <div>
              <strong>
                {currentEnforced ? "Blocking at the boundary" : "Observing only"}
              </strong>
              <span>
                {currentEnforced
                  ? "Deny and require_approval verdicts stop execution before the tool runs."
                  : "Calls are evaluated and audited, but the would-be verdict is recorded instead of enforced."}
              </span>
            </div>
          </div>

          <div className="ws-navy-kv">
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
                      <Dot tone="error" /> not ready
                    </span>
                  ) : (
                    "Checking…"
                  ),
                },
                {
                  label: "Detectors",
                  value: health.data?.detectors.join(", ") || "—",
                  mono: true,
                },
                {
                  label: "Auth",
                  value: health.data
                    ? health.data.auth_required
                      ? "API key required by gateway"
                      : "Open dev gateway (no API key)"
                    : "—",
                },
              ]}
            />
          </div>

          <p className="ws-navy-note">
            The global switch is admin-key gated and audit-logged. Isolated red-team
            runs never change it.
          </p>

          <button
            type="button"
            className={cn("ws-btn is-block", currentEnforced ? "is-danger" : "is-lime")}
            onClick={() => {
              setToggleFailure(null);
              setToggleSuccess(null);
              setConfirmEnforce(true);
            }}
            disabled={!enforce.data || togglePending}
          >
            {currentEnforced ? "Turn enforcement OFF" : "Turn enforcement ON"}
          </button>
        </NavyFeaturePanel>
      </div>

      <div className="ws-grid ws-grid-main">
        <Card>
          <CardHead
            title="Recent audit events"
            subtitle="Newest first · append-only JSONL trail"
            icon={Database}
            actions={
              <Link href="/workspace/audit" className="ws-link">
                Full audit <ArrowRight className="h-3 w-3" />
              </Link>
            }
          />
          <CardBody flush>
            {audit.data ? (
              recentAudit.length ? (
                <div className="ws-table-wrap">
                  <table className="ws-table">
                    <thead>
                      <tr>
                        <th>Time</th>
                        <th>Decision</th>
                        <th>Tool</th>
                        <th>Source</th>
                        <th>Agent / session</th>
                        <th>Call ID</th>
                      </tr>
                    </thead>
                    <tbody>
                      {recentAudit.map((entry) => {
                        const metadata = entry.metadata ?? {};
                        const agent =
                          String(metadata.agent ?? metadata.agent_id ?? "—") || "—";
                        const session =
                          String(
                            metadata.session_id ??
                              metadata.session ??
                              metadata.thread_id ??
                              "",
                          ) || "";
                        return (
                          <tr key={`${entry.call_id}-${String(entry.ts)}`}>
                            <td className="is-nowrap text-[#777777]">
                              {formatTimestamp(entry.ts)}
                            </td>
                            <td>
                              <DecisionBadge decision={entry.decision} short />
                            </td>
                            <td className="font-mono text-[10.5px]">{entry.tool}</td>
                            <td>
                              <SourceBadge source={entry.source} />
                            </td>
                            <td className="text-[10.5px]">
                              {agent}
                              {session ? (
                                <span className="block font-mono text-[9px] text-[#8b8881]">
                                  {session}
                                </span>
                              ) : null}
                            </td>
                            <td>
                              <Link
                                href={`/workspace/audit?call=${encodeURIComponent(entry.call_id)}`}
                                className={cn(
                                  "ws-link font-mono text-[9.5px]",
                                  decisionClass(entry.decision),
                                )}
                              >
                                {entry.call_id}
                              </Link>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="ws-empty">
                  <span className="ws-empty-icon">
                    <Database className="h-5 w-5" />
                  </span>
                  <strong>No audit entries yet.</strong>
                  <p>
                    Send a call through <code className="ws-mono">POST /v1/check</code>{" "}
                    from the Activity Monitor to create the first decision record.
                  </p>
                </div>
              )
            ) : audit.failure ? (
              <div className="p-4">
                <ErrorState failure={audit.failure} onRetry={audit.refresh} compact />
              </div>
            ) : (
              <div className="p-4">
                <LoadingState rows={2} />
              </div>
            )}
          </CardBody>
        </Card>

        <Card>
          <CardHead
            title="Threat overview"
            subtitle="Detector findings with inferred presentation categories"
            icon={ShieldAlert}
            actions={
              <Link href="/workspace/threats" className="ws-link">
                Investigate <ArrowRight className="h-3 w-3" />
              </Link>
            }
          />
          <CardBody>
            {threats.data ? (
              <div className="ws-stack-sm">
                <div className="ws-threat-scale">
                  <span className="ws-threat-scale-row is-high">
                    <span>High</span>
                    <span className="ws-threat-scale-track">
                      <span
                        style={{
                          width: `${threats.data.total > 0 ? (threats.data.severity.high / threats.data.total) * 100 : 0}%`,
                        }}
                      />
                    </span>
                    <strong>{formatNumber(threats.data.severity.high)}</strong>
                  </span>
                  <span className="ws-threat-scale-row is-medium">
                    <span>Medium</span>
                    <span className="ws-threat-scale-track">
                      <span
                        style={{
                          width: `${threats.data.total > 0 ? (threats.data.severity.medium / threats.data.total) * 100 : 0}%`,
                        }}
                      />
                    </span>
                    <strong>{formatNumber(threats.data.severity.medium)}</strong>
                  </span>
                  <span className="ws-threat-scale-row is-low">
                    <span>Low</span>
                    <span className="ws-threat-scale-track">
                      <span
                        style={{
                          width: `${threats.data.total > 0 ? (threats.data.severity.low / threats.data.total) * 100 : 0}%`,
                        }}
                      />
                    </span>
                    <strong>{formatNumber(threats.data.severity.low)}</strong>
                  </span>
                </div>
                <div className="ws-divider" />
                {recentThreats.length ? (
                  recentThreats.map((event) => (
                    <Link
                      key={event.threat_id}
                      href={`/workspace/threats?event=${encodeURIComponent(event.threat_id)}`}
                      className="ws-list-row"
                    >
                      <span className="ws-list-row-copy">
                        <span className="ws-list-row-title">{event.tool}</span>
                        <span className="ws-list-row-sub">
                          {event.category_label} · {event.detector} ·{" "}
                          {event.score.toFixed(2)}
                        </span>
                      </span>
                      <DecisionBadge decision={event.decision} short />
                    </Link>
                  ))
                ) : (
                  <p className="ws-hint">
                    No detector-flagged events in the retained audit sample.
                  </p>
                )}
              </div>
            ) : threats.failure ? (
              <ErrorState failure={threats.failure} onRetry={threats.refresh} compact />
            ) : (
              <LoadingState rows={2} />
            )}
          </CardBody>
        </Card>
      </div>

      <div className="ws-grid ws-grid-3">
        <Card>
          <CardHead
            title="Pending human decisions"
            subtitle="Single-use, argument-hash-bound approvals"
            icon={UserCheck}
            actions={
              <Link href="/workspace/approvals" className="ws-link">
                Approval Center <ArrowRight className="h-3 w-3" />
              </Link>
            }
          />
          <CardBody>
            {approvals.data ? (
              approvals.data.pending.length ? (
                <div className="ws-stack-sm">
                  {approvals.data.pending.slice(0, 3).map((entry) => (
                    <div key={entry.call_id} className="ws-list-card">
                      <div className="ws-between">
                        <span className="font-mono text-[11px] font-semibold">
                          {entry.tool}
                        </span>
                        <span className="ws-badge is-hold">pending</span>
                      </div>
                      <p className="mt-1 line-clamp-2 text-[10.5px] leading-relaxed text-[#777777]">
                        {entry.reasons[0]?.detail ?? "Held by policy."}
                      </p>
                      <div className="mt-1.5 flex items-center justify-between text-[9.5px] text-[#8b8881]">
                        <span className="font-mono">{entry.call_id}</span>
                        <span>{formatRelative(entry.ts)}</span>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="ws-empty min-h-[110px]">
                  <span className="ws-empty-icon">
                    <BadgeCheck className="h-5 w-5" />
                  </span>
                  <strong>No calls are waiting for a human.</strong>
                  <p>The approval queue is clear in the current audit window.</p>
                </div>
              )
            ) : approvals.failure ? (
              <ErrorState failure={approvals.failure} onRetry={approvals.refresh} compact />
            ) : (
              <LoadingState rows={2} />
            )}
          </CardBody>
        </Card>

        <Card>
          <CardHead
            title="Top tools by volume"
            subtitle="Observed calls in the selected window"
            icon={Bot}
            actions={
              <Link href="/workspace/tools" className="ws-link">
                Tools <ArrowRight className="h-3 w-3" />
              </Link>
            }
          />
          <CardBody>
            {metrics.data ? (
              <Bars
                rows={topTools.map((tool) => ({
                  label: tool.tool,
                  value: tool.total,
                  note: `${tool.total} · ${tool.deny} deny`,
                  tone:
                    tool.deny > 0
                      ? "red"
                      : tool.require_approval > 0
                        ? "purple"
                        : "lime",
                }))}
                empty="No tool calls in this window."
              />
            ) : metrics.failure ? (
              <ErrorState failure={metrics.failure} onRetry={metrics.refresh} compact />
            ) : (
              <LoadingState rows={2} />
            )}
          </CardBody>
        </Card>

        <Card>
          <CardHead
            title="Active agent sessions"
            subtitle="Derived from audit metadata keys only"
            icon={Users}
            actions={
              <Link href="/workspace/agents" className="ws-link">
                Sessions <ArrowRight className="h-3 w-3" />
              </Link>
            }
          />
          <CardBody>
            {agents.data ? (
              topSessions.length ? (
                <div className="ws-stack-sm">
                  {topSessions.map((session) => (
                    <Link
                      key={`${session.agent}-${session.session_id}`}
                      href={`/workspace/agents?session=${encodeURIComponent(session.session_id)}`}
                      className="ws-list-row"
                    >
                      <span className="ws-list-row-copy">
                        <span className="ws-list-row-title">{session.agent}</span>
                        <span className="ws-list-row-sub font-mono">
                          {session.session_id}
                        </span>
                      </span>
                      <span className="ws-list-row-side">
                        <strong>{session.calls} calls</strong>
                        <span>{formatRelative(session.last_seen)}</span>
                      </span>
                    </Link>
                  ))}
                </div>
              ) : (
                <div className="ws-empty min-h-[110px]">
                  <span className="ws-empty-icon">
                    <Users className="h-5 w-5" />
                  </span>
                  <strong>No agent/session metadata observed.</strong>
                  <p>
                    Calls without agent or session metadata are still audited, but
                    cannot be grouped into a session.
                  </p>
                </div>
              )
            ) : agents.failure ? (
              <ErrorState failure={agents.failure} onRetry={agents.refresh} compact />
            ) : (
              <LoadingState rows={2} />
            )}
          </CardBody>
        </Card>
      </div>

      <Banner tone="purple" icon={ShieldCheck}>
        <strong>Live vs historical.</strong> This page polls the gateway every 15
        seconds through the server-side proxy. Metrics are bounded to the most recent
        500 audit entries and the selected window; the API explicitly reports when
        that sample limit is reached. The gateway does not record processing
        duration, so no timing claim is shown here.
      </Banner>

      <ConfirmDialog
        open={confirmEnforce}
        title={currentEnforced ? "Turn global enforcement OFF?" : "Turn global enforcement ON?"}
        description={
          currentEnforced
            ? "Every new gateway call will still be evaluated, detected and audited, but the final decision will be ALLOW with an explicit enforcement_disabled reason naming the would-be verdict. This changes the live gateway, not just this page."
            : "New gateway calls will be enforced again: deny and require_approval verdicts will stop execution at the boundary. This changes the live gateway, not just this page."
        }
        confirmLabel={currentEnforced ? "Turn OFF" : "Turn ON"}
        tone={currentEnforced ? "danger" : "primary"}
        pending={togglePending}
        onConfirm={applyEnforcement}
        onCancel={() => setConfirmEnforce(false)}
      />
    </div>
  );
}
