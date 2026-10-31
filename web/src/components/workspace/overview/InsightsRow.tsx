"use client";

import { Microscope, Network } from "lucide-react";
import { formatNumber } from "@/lib/api/format";
import type { MetricsResponse } from "@/lib/api/types";
import type { UseLiveDataResult } from "@/lib/hooks/use-live-data";
import {
  Bars,
  Card,
  CardBody,
  CardHead,
  EmptyState,
  ErrorState,
  LoadingState,
} from "@/components/workspace/ui";

export function InsightsRow({
  metrics,
}: {
  metrics: UseLiveDataResult<MetricsResponse>;
}) {
  const detectors = metrics.data?.detectors ?? [];
  const sources = metrics.data?.sources ?? [];

  return (
    <>
      <Card>
        <CardHead
          title="Detector performance"
          subtitle="Runs, flagged threats and errors in the selected window"
          icon={Microscope}
        />
        <CardBody flush>
          {metrics.data ? (
            detectors.length ? (
              <div className="ws-table-wrap">
                <table className="ws-table">
                  <thead>
                    <tr>
                      <th>Detector</th>
                      <th>Runs</th>
                      <th>Threats</th>
                      <th>Errors</th>
                      <th>Avg score</th>
                    </tr>
                  </thead>
                  <tbody>
                    {detectors.map((detector) => (
                      <tr key={detector.detector}>
                        <td className="font-mono ws-fs-body">{detector.detector}</td>
                        <td className="ws-fs-body">{formatNumber(detector.runs)}</td>
                        <td className="ws-fs-body">{formatNumber(detector.threats)}</td>
                        <td className="ws-fs-body">{formatNumber(detector.errors)}</td>
                        <td className="font-mono ws-fs-body">
                          {detector.avg_score === null ? "—" : detector.avg_score.toFixed(2)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <EmptyState
                title="No detector runs in this window."
                description="Detector runs recorded by the gateway in the selected window appear here."
                icon={Microscope}
              />
            )
          ) : metrics.failure ? (
            <div className="p-4">
              <ErrorState failure={metrics.failure} onRetry={() => void metrics.refresh()} compact />
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
          title="Source provenance mix"
          subtitle="Call-source mix in the selected window · trust comes from the token, not the label"
          icon={Network}
        />
        <CardBody>
          {metrics.data ? (
            sources.length ? (
              <div className="ws-stack-sm">
                <Bars
                  rows={sources.map((row) => ({
                    label: row.source,
                    value: row.count,
                    note: `${formatNumber(row.count)}`,
                    tone: row.source.toLowerCase().includes("untrust")
                      ? ("deny" as const)
                      : undefined,
                  }))}
                />
                <p className="ws-hint">
                  Provenance is assigned by the gateway at ingest. Untrusted
                  content is inspected before any tool runs.
                </p>
              </div>
            ) : (
              <EmptyState
                title="No source data in this window."
                description="The gateway records a provenance source for every evaluated call."
                icon={Network}
              />
            )
          ) : metrics.failure ? (
            <ErrorState failure={metrics.failure} onRetry={() => void metrics.refresh()} compact />
          ) : (
            <LoadingState rows={2} />
          )}
        </CardBody>
      </Card>
    </>
  );
}
