"use client";

import { ShieldCheck } from "lucide-react";
import type {
  AgentsResponse,
  ApprovalsResponse,
  AuditResponse,
  EnforceResponse,
  HealthResponse,
  MetricsResponse,
  PolicyResponse,
  ReadyResponse,
  ThreatsResponse,
} from "@/lib/api/types";
import { useLiveData } from "@/lib/hooks/use-live-data";
import { Banner, ErrorState, StaleBanner } from "@/components/workspace/ui";
import { timeWindowLabels, useTimeWindow } from "@/components/workspace/time-window";
import { ActiveSessionsCard } from "./overview/ActiveSessionsCard";
import { DecisionVolumeCard } from "./overview/DecisionVolumeCard";
import { EnforcementStatusCard } from "./overview/EnforcementStatusCard";
import { InsightsRow } from "./overview/InsightsRow";
import { BenchmarkPanel, ScorecardPanel } from "./proof";
import { KpiRow } from "./overview/KpiRow";
import { OverviewHeader } from "./overview/OverviewHeader";
import { PendingApprovals } from "./overview/PendingApprovals";
import { RecentAuditEvents } from "./overview/RecentAuditEvents";
import { ThreatOverview } from "./overview/ThreatOverview";
import { TopToolsCard } from "./overview/TopToolsCard";

export function OverviewClient() {
  const { windowKey } = useTimeWindow();

  const health = useLiveData<HealthResponse>("/health", { intervalMs: 15_000 });
  const ready = useLiveData<ReadyResponse>("/ready", { intervalMs: 15_000 });
  const enforce = useLiveData<EnforceResponse>("/v1/enforce", { intervalMs: 15_000 });
  const policy = useLiveData<PolicyResponse>("/v1/policy", { intervalMs: 30_000 });
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
      policy.refresh(),
      metrics.refresh(),
      threats.refresh(),
      approvals.refresh(),
      agents.refresh(),
      audit.refresh(),
    ]);
  };

  const pending = approvals.data?.summary.pending ?? metrics.data?.totals.pending_approvals ?? 0;

  const updatedAt = Math.max(
    health.lastUpdated ?? 0,
    ready.lastUpdated ?? 0,
    enforce.lastUpdated ?? 0,
    metrics.lastUpdated ?? 0,
    threats.lastUpdated ?? 0,
    approvals.lastUpdated ?? 0,
    agents.lastUpdated ?? 0,
    audit.lastUpdated ?? 0,
  );

  const gatewayDown = health.failure && !health.data;
  const globalStale = metrics.failure && metrics.data;

  return (
    <div className="ws-stack">
      <OverviewHeader
        refreshing={refreshing}
        onRefresh={refreshAll}
        updatedAt={updatedAt > 0 ? updatedAt : null}
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

      <KpiRow metrics={metrics} windowLabel={timeWindowLabels[windowKey]} pending={pending} />

      <div className="ws-grid ws-grid-main">
        <DecisionVolumeCard metrics={metrics} windowLabel={timeWindowLabels[windowKey]} />
        <EnforcementStatusCard
          enforce={enforce}
          health={health}
          ready={ready}
          policy={policy}
          totals={metrics.data?.totals ?? null}
          windowLabel={timeWindowLabels[windowKey]}
          onToggleApplied={() => {
            void Promise.all([metrics.refresh(), audit.refresh()]);
          }}
        />
      </div>

      <div className="ws-grid ws-grid-main-wide">
        <RecentAuditEvents audit={audit} />
        <ThreatOverview threats={threats} />
      </div>

      <div className="ws-grid ws-grid-3">
        <PendingApprovals approvals={approvals} />
        <TopToolsCard metrics={metrics} />
        <ActiveSessionsCard agents={agents} />
      </div>

      <div className="ws-grid ws-grid-2">
        <InsightsRow metrics={metrics} />
      </div>

      <div className="ws-grid ws-grid-2">
        <BenchmarkPanel compact />
        <ScorecardPanel compact />
      </div>

      <Banner tone="purple" icon={ShieldCheck}>
        <strong>Live vs historical.</strong> This page polls the gateway every 15
        seconds through the server-side proxy. Metrics are bounded to the most recent
        500 audit entries and the selected window; the API explicitly reports when
        that sample limit is reached. The gateway does not record processing
        duration, so no timing claim is shown here.
      </Banner>
    </div>
  );
}
