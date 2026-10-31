"use client";

import {
  Activity,
  ArrowRight,
  BarChart3,
  Clock3,
  Fingerprint,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  UserCheck,
  Users,
} from "lucide-react";
import Link from "next/link";
import { useMemo } from "react";
import {
  formatDelta,
  formatNumber,
  formatRelative,
} from "@/lib/api/format";
import type {
  AgentsResponse,
  AuditResponse,
  MetricsResponse,
  ThreatsResponse,
} from "@/lib/api/types";
import { useLiveData } from "@/lib/hooks/use-live-data";
import { cn } from "@/lib/utils";
import {
  Bars,
  Card,
  CardBody,
  CardHead,
  Distribution,
  EmptyState,
  ErrorState,
  EventRow,
  LiveMeta,
  LoadingState,
  PageHeader,
  ProvenanceIndicator,
  Sparkline,
  StaleBanner,
  StatCard,
  TrendChart,
} from "@/components/workspace/ui";
import {
  timeWindowLabels,
  useTimeWindow,
} from "@/components/workspace/time-window";

export function AnalyticsClient() {
  const { windowKey } = useTimeWindow();
  const metrics = useLiveData<MetricsResponse>(
    `/v1/metrics?window=${windowKey}&limit=500`,
    { intervalMs: 15_000 },
  );
  const threats = useLiveData<ThreatsResponse>("/v1/threats?limit=500", {
    intervalMs: 20_000,
  });
  const agents = useLiveData<AgentsResponse>("/v1/agents?limit=500", {
    intervalMs: 20_000,
  });
  const audit = useLiveData<AuditResponse>("/v1/audit?limit=50", {
    intervalMs: 15_000,
  });

  const refreshing =
    metrics.isRefreshing ||
    threats.isRefreshing ||
    agents.isRefreshing ||
    audit.isRefreshing;

  const refreshAll = () => {
    void Promise.all([
      metrics.refresh(),
      threats.refresh(),
      agents.refresh(),
      audit.refresh(),
    ]);
  };

  const totals = metrics.data?.totals;
  const series = useMemo(() => metrics.data?.series ?? [], [metrics.data]);
  const distribution = metrics.data?.decision_distribution ?? [];
  const allowCount = distribution.find((row) => row.decision === "allow")?.count ?? 0;
  const holdCount =
    distribution.find((row) => row.decision === "require_approval")?.count ?? 0;
  const denyCount = distribution.find((row) => row.decision === "deny")?.count ?? 0;

  const evaluated = totals?.evaluated ?? 0;
  const denyRate = evaluated > 0 ? ((totals?.blocked ?? 0) / evaluated) * 100 : null;
  const holdRate = evaluated > 0 ? ((totals?.held ?? 0) / evaluated) * 100 : null;
  const allowRate = evaluated > 0 ? ((totals?.allowed ?? 0) / evaluated) * 100 : null;

  const topSessions = useMemo(
    () => [...(agents.data?.sessions ?? [])].sort((a, b) => b.calls - a.calls).slice(0, 6),
    [agents.data],
  );
  const recentAudit = useMemo(
    () => (audit.data?.entries ?? []).slice(0, 8),
    [audit.data],
  );

  const allowSeries = useMemo(() => series.map((point) => point.allow), [series]);
  const denySeries = useMemo(() => series.map((point) => point.deny), [series]);
  const holdSeries = useMemo(
    () => series.map((point) => point.require_approval),
    [series],
  );
  const totalSeries = useMemo(() => series.map((point) => point.total), [series]);

  return (
    <div className="ws-stack">
      <PageHeader
        eyebrow="Analytics"
        title={
          <>
            Signal, <em>not noise.</em>
          </>
        }
        description="Decision volume, enforcement mix, provenance and detector performance for the selected window. Every series is computed from the gateway audit trail; no values are estimated or simulated."
        actions={
          <>
            <Link href="/workspace/audit" className="ws-btn is-sm is-ghost">
              Open audit <ArrowRight className="h-3.5 w-3.5" />
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

      {metrics.failure && metrics.data ? (
        <StaleBanner
          failure={metrics.failure}
          lastUpdated={metrics.lastUpdated}
          onRetry={refreshAll}
        />
      ) : null}

      {metrics.failure && !metrics.data ? (
        <ErrorState failure={metrics.failure} onRetry={refreshAll} />
      ) : (
        <>
          <div className="ws-grid ws-grid-4 ws-metric-grid">
            <StatCard
              loading={!metrics.data && !metrics.failure}
          label="Calls evaluated"
              value={
                metrics.data ? formatNumber(totals?.evaluated) : "—"
              }
              meta={
                metrics.data ? (
                  <>
                    <Clock3 className="h-3 w-3" /> {timeWindowLabels[windowKey]} ·{" "}
                    {formatDelta(metrics.data.deltas.evaluated)}
                  </>
                ) : (
                  "Gateway unreachable — retry"
                )
              }
              icon={Activity}
              tone="cream"
              visual={<Sparkline values={totalSeries} tone="navy" />}
            />
            <StatCard
              loading={!metrics.data && !metrics.failure}
          label="Allowed"
              value={metrics.data ? formatNumber(totals?.allowed) : "—"}
              meta={
                metrics.data
                  ? `${allowRate === null ? "—" : allowRate.toFixed(1)}% of evaluated`
                  : "Gateway unreachable — retry"
              }
              icon={ShieldCheck}
              tone="lime"
              visual={<Sparkline values={allowSeries} tone="allow" />}
            />
            <StatCard
              loading={!metrics.data && !metrics.failure}
          label="Denied"
              value={metrics.data ? formatNumber(totals?.blocked) : "—"}
              meta={
                metrics.data
                  ? `${denyRate === null ? "—" : denyRate.toFixed(1)}% of evaluated`
                  : "Gateway unreachable — retry"
              }
              icon={ShieldAlert}
              tone="peach"
              visual={<Sparkline values={denySeries} tone="deny" />}
            />
            <StatCard
              loading={!metrics.data && !metrics.failure}
          label="Held for approval"
              value={metrics.data ? formatNumber(totals?.held) : "—"}
              meta={
                metrics.data
                  ? `${holdRate === null ? "—" : holdRate.toFixed(1)}% · ${formatNumber(totals?.pending_approvals)} pending now`
                  : "Gateway unreachable — retry"
              }
              icon={UserCheck}
              tone="purple"
              visual={<Sparkline values={holdSeries} tone="hold" />}
            />
          </div>

          <div className="ws-grid ws-grid-main">
            <Card>
              <CardHead
                title="Decision volume"
                subtitle={`${timeWindowLabels[windowKey]} window · ${formatNumber(metrics.data?.sample.events_in_window)} events read`}
                icon={BarChart3}
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
                    <p className="ws-hint">
                      {formatNumber(metrics.data.sample.entries_read)} audit entries read
                      (limit {metrics.data.sample.limit})
                      {metrics.data.sample.truncated
                        ? " · sample limit reached; older retained entries are outside this view"
                        : ""}
                      . {metrics.data.notes.durations}
                    </p>
                  </div>
                ) : null}
              </CardBody>
            </Card>

            <Card>
              <CardHead
                title="Detector performance"
                subtitle="Runs, findings and scores recorded by the gateway"
                icon={Fingerprint}
                actions={<span className="ws-count-pill">real output</span>}
              />
              <CardBody>
                {metrics.isLoading ? (
                  <LoadingState rows={2} />
                ) : metrics.data?.detectors.length ? (
                  <div className="ws-stack-sm">
                    {metrics.data.detectors.map((detector) => (
                      <div className="ws-detector-row" key={detector.detector}>
                        <span className="ws-detector-name">
                          <strong>{detector.detector}</strong>
                          <span>{formatNumber(detector.runs)} runs</span>
                        </span>
                        <span className="ws-detector-stats">
                          <span>
                            <strong>{formatNumber(detector.threats)}</strong> threats
                          </span>
                          <span>
                            <strong>{formatNumber(detector.errors)}</strong> errors
                          </span>
                          <span>
                            <strong>
                              {detector.avg_score === null
                                ? "—"
                                : detector.avg_score.toFixed(2)}
                            </strong>{" "}
                            avg score
                          </span>
                        </span>
                      </div>
                    ))}
                    <p className="ws-hint">
                      {metrics.data.notes.detectors ??
                        "Detector rows reflect only the retained audit sample."}
                    </p>
                  </div>
                ) : (
                  <EmptyState
                    title="No detector runs in this window."
                    description="Send a call through the boundary or widen the time window."
                    icon={Fingerprint}
                  />
                )}
              </CardBody>
            </Card>
          </div>

          <div className="ws-grid ws-grid-3">
            <Card>
              <CardHead
                title="Source provenance"
                subtitle="Resolved source on audited calls"
                icon={Fingerprint}
              />
              <CardBody>
                {metrics.data ? (
                  <ProvenanceIndicator counts={metrics.data.sources} />
                ) : (
                  <LoadingState rows={2} />
                )}
              </CardBody>
            </Card>

            <Card>
              <CardHead
                title="Top tools"
                subtitle="Observed volume in the selected window"
                icon={BarChart3}
              />
              <CardBody>
                {metrics.data ? (
                  <Bars
                    rows={(metrics.data.top_tools ?? []).slice(0, 6).map((tool) => ({
                      label: tool.tool,
                      value: tool.total,
                      note: `${tool.total} · ${tool.deny} deny`,
                      tone:
                        tool.deny > 0
                          ? "deny"
                          : tool.require_approval > 0
                            ? "hold"
                            : "allow",
                    }))}
                  />
                ) : (
                  <LoadingState rows={2} />
                )}
              </CardBody>
            </Card>

            <Card>
              <CardHead
                title="Most active sessions"
                subtitle="Projected from audit metadata"
                icon={Users}
              />
              <CardBody>
                {agents.data ? (
                  topSessions.length ? (
                    <div className="ws-stack-sm">
                      {topSessions.map((session) => (
                        <Link
                          key={`${session.agent}-${session.session_id}`}
                          href={`/workspace/agents?session=${encodeURIComponent(session.session_id)}`}
                          className="ws-session-row"
                        >
                          <span>
                            <strong>{session.agent}</strong>
                            <span>{session.session_id}</span>
                          </span>
                          <span>
                            <strong>{formatNumber(session.calls)}</strong>
                            <span>{formatRelative(session.last_seen)}</span>
                          </span>
                        </Link>
                      ))}
                    </div>
                  ) : (
                    <EmptyState
                      title="No session metadata observed."
                      description="Calls without agent or session metadata are still audited."
                      icon={Users}
                    />
                  )
                ) : agents.failure ? (
                  <ErrorState failure={agents.failure} onRetry={agents.refresh} compact />
                ) : (
                  <LoadingState rows={2} />
                )}
              </CardBody>
            </Card>
          </div>

          <Card>
            <CardHead
              title="Recent decisions"
              subtitle="Newest audited records · no derived metrics"
              icon={Activity}
              actions={
                <Link href="/workspace/audit" className="ws-link">
                  Full audit <ArrowRight className="h-3 w-3" />
                </Link>
              }
            />
            <CardBody flush>
              {audit.data ? (
                recentAudit.length ? (
                  <div className="ws-event-list">
                    {recentAudit.map((entry) => {
                      const metadata = entry.metadata ?? {};
                      const agent = String(
                        metadata.agent ?? metadata.agent_id ?? "unknown agent",
                      );
                      return (
                        <EventRow
                          key={`${entry.call_id}-${String(entry.ts)}`}
                          decision={entry.decision}
                          tool={entry.tool}
                          source={entry.source}
                          meta={agent}
                          time={formatRelative(entry.ts)}
                          href={`/workspace/audit?call=${encodeURIComponent(entry.call_id)}`}
                        />
                      );
                    })}
                  </div>
                ) : (
                  <EmptyState
                    title="No decisions recorded yet."
                    description="Use the Activity Monitor to send a boundary check."
                    icon={Activity}
                  />
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

          <div className="ws-banner is-purple">
            <BarChart3 className="mt-0.5 h-4 w-4 shrink-0" />
            <div>
              <strong>What this page measures.</strong>{" "}
              {metrics.data?.notes.windows ??
                "Analytics are bounded to the retained audit sample and the selected time window."}{" "}
              {threats.data
                ? `${formatNumber(threats.data.total)} detector findings are retained across the threat sample.`
                : "Threat totals are not loaded."}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
