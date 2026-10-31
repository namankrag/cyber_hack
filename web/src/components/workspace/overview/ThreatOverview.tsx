"use client";

import { useMemo } from "react";
import { ArrowRight, ShieldAlert } from "lucide-react";
import Link from "next/link";
import { formatNumber } from "@/lib/api/format";
import type { ThreatsResponse } from "@/lib/api/types";
import type { UseLiveDataResult } from "@/lib/hooks/use-live-data";
import {
  Card,
  CardBody,
  CardHead,
  DecisionBadge,
  EmptyState,
  ErrorState,
  InferredBadge,
  LoadingState,
} from "@/components/workspace/ui";

export function ThreatOverview({
  threats,
}: {
  threats: UseLiveDataResult<ThreatsResponse>;
}) {
  const recentThreats = useMemo(
    () => (threats.data?.events ?? []).slice(0, 5),
    [threats.data],
  );

  return (
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
                    <span className="ws-list-row-title">
                      {event.tool}{" "}
                      {event.category_inferred ? <InferredBadge /> : null}
                    </span>
                    <span className="ws-list-row-sub">
                      {event.category_label} · {event.detector} ·{" "}
                      {event.score.toFixed(2)}
                    </span>
                  </span>
                  <DecisionBadge decision={event.decision} short />
                </Link>
              ))
            ) : (
              <EmptyState
                title="No threat findings in the retained sample."
                description="Detector-flagged events from the retained audit sample appear here."
                icon={ShieldAlert}
              />
            )}
            <p className="ws-hint">{threats.data.classification_note}</p>
          </div>
        ) : threats.failure ? (
          <ErrorState failure={threats.failure} onRetry={() => void threats.refresh()} compact />
        ) : (
          <LoadingState rows={2} />
        )}
      </CardBody>
    </Card>
  );
}
