"use client";

import { Activity, Clock3, ShieldAlert, ShieldCheck, UserCheck } from "lucide-react";
import { formatDelta, formatNumber } from "@/lib/api/format";
import type { MetricsResponse } from "@/lib/api/types";
import type { UseLiveDataResult } from "@/lib/hooks/use-live-data";
import { ErrorState, Sparkline, StatCard } from "@/components/workspace/ui";

function percentLabel(rate: number | null, suffix: string): string {
  if (rate === null) return `— ${suffix}`;
  return `${rate.toFixed(1)}% ${suffix}`;
}

function hasTrend(values: number[]): boolean {
  return values.filter((value) => value > 0).length >= 2;
}

export function KpiRow({
  metrics,
  windowLabel,
  pending,
}: {
  metrics: UseLiveDataResult<MetricsResponse>;
  windowLabel: string;
  pending: number;
}) {
  if (metrics.failure && !metrics.data) {
    return <ErrorState failure={metrics.failure} onRetry={() => void metrics.refresh()} />;
  }

  const totals = metrics.data?.totals;
  const evaluated = totals?.evaluated ?? 0;
  const allowRate = evaluated > 0 ? ((totals?.allowed ?? 0) / evaluated) * 100 : null;
  const denyRate = evaluated > 0 ? ((totals?.blocked ?? 0) / evaluated) * 100 : null;
  const holdRate = evaluated > 0 ? ((totals?.held ?? 0) / evaluated) * 100 : null;

  const series = metrics.data?.series ?? [];
  const totalSeries = series.map((point) => point.total);
  const allowSeries = series.map((point) => point.allow);
  const denySeries = series.map((point) => point.deny);
  const holdSeries = series.map((point) => point.require_approval);

  const delta =
    metrics.data && metrics.data.deltas.evaluated != null
      ? formatDelta(metrics.data.deltas.evaluated)
      : "No previous period";

  const loading = !metrics.data && !metrics.failure;

  return (
    <div className="ws-grid ws-grid-4 ws-metric-grid">
      <StatCard
        loading={loading}
        label="Calls evaluated"
        value={metrics.data ? formatNumber(totals?.evaluated) : "—"}
        meta={
          metrics.data ? (
            <>
              <Clock3 className="h-3 w-3" /> {windowLabel} · {delta}
            </>
          ) : (
            "Gateway unreachable — retry"
          )
        }
        icon={Activity}
        tone="cream"
        visual={hasTrend(totalSeries) ? <Sparkline values={totalSeries} tone="navy" /> : undefined}
      />
      <StatCard
        loading={loading}
        label="Allowed"
        value={metrics.data ? formatNumber(totals?.allowed) : "—"}
        meta={metrics.data ? percentLabel(allowRate, "· explicit policy allow") : "Gateway unreachable — retry"}
        icon={ShieldCheck}
        tone="lime"
        visual={hasTrend(allowSeries) ? <Sparkline values={allowSeries} tone="allow" /> : undefined}
      />
      <StatCard
        loading={loading}
        label="Denied"
        value={metrics.data ? formatNumber(totals?.blocked) : "—"}
        meta={metrics.data ? percentLabel(denyRate, "· never reached the tool") : "Gateway unreachable — retry"}
        icon={ShieldAlert}
        tone="peach"
        visual={hasTrend(denySeries) ? <Sparkline values={denySeries} tone="deny" /> : undefined}
      />
      <StatCard
        loading={loading}
        label="Held for approval"
        value={metrics.data ? formatNumber(totals?.held) : "—"}
        meta={
          metrics.data ? (
            <>
              <UserCheck className="h-3 w-3" /> {percentLabel(holdRate, `· ${formatNumber(pending)} pending now`)}
            </>
          ) : (
            "Gateway unreachable — retry"
          )
        }
        icon={UserCheck}
        tone="purple"
        visual={hasTrend(holdSeries) ? <Sparkline values={holdSeries} tone="hold" /> : undefined}
      />
    </div>
  );
}
