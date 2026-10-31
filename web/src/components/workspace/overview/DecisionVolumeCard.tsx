"use client";

import { Activity, LockKeyhole } from "lucide-react";
import { formatNumber } from "@/lib/api/format";
import type { MetricsResponse } from "@/lib/api/types";
import type { UseLiveDataResult } from "@/lib/hooks/use-live-data";
import {
  Card,
  CardBody,
  CardHead,
  Distribution,
  ErrorState,
  LiveMeta,
  LoadingState,
  TrendChart,
} from "@/components/workspace/ui";

export function DecisionVolumeCard({
  metrics,
  windowLabel,
}: {
  metrics: UseLiveDataResult<MetricsResponse>;
  windowLabel: string;
}) {
  const distribution = metrics.data?.decision_distribution ?? [];
  const allowCount = distribution.find((row) => row.decision === "allow")?.count ?? 0;
  const holdCount =
    distribution.find((row) => row.decision === "require_approval")?.count ?? 0;
  const denyCount = distribution.find((row) => row.decision === "deny")?.count ?? 0;

  return (
    <Card>
      <CardHead
        title="Decision volume"
        subtitle={`${windowLabel} window · ${formatNumber(metrics.data?.sample.events_in_window)} events read from the audit trail`}
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
          <ErrorState failure={metrics.failure} onRetry={() => void metrics.refresh()} compact />
        ) : metrics.data ? (
          <div className="ws-stack">
            <Distribution allow={allowCount} hold={holdCount} deny={denyCount} percentages />
            <div className="ws-divider" />
            <div>
              <div className="ws-between mb-1">
                <span className="ws-label">Volume by bucket</span>
                <span className="ws-hint">
                  {metrics.data.series.length} buckets · {windowLabel}
                </span>
              </div>
              <TrendChart series={metrics.data.series} />
            </div>
            <div className="ws-banner">
              <LockKeyhole className="mt-0.5 h-4 w-4 shrink-0" />
              <div>
                <strong>Data window:</strong> {windowLabel} ·{" "}
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
  );
}
