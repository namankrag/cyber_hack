"use client";

import { ArrowRight, RefreshCw } from "lucide-react";
import Link from "next/link";
import { formatRelative } from "@/lib/api/format";
import { cn } from "@/lib/utils";
import { PageHeader } from "@/components/workspace/ui";
import { SkeletonPill } from "@/components/workspace/ui";

export function OverviewHeader({
  refreshing,
  onRefresh,
  updatedAt,
}: {
  refreshing: boolean;
  onRefresh: () => void;
  updatedAt: number | null;
}) {
  return (
    <PageHeader
      eyebrow="Operational overview"
      title="Security Overview"
      description="A real-time view of AgentShield gateway activity, enforcement decisions, threat signals, pending approvals, and recent audit events."
      actions={
        <>
          <Link href="/workspace/analytics" className="ws-btn is-sm is-ghost">
            Analytics <ArrowRight className="h-3.5 w-3.5" />
          </Link>
          {updatedAt ? (
            <span className="ws-hint" title="Newest successful poll across all panels">
              Updated {formatRelative(updatedAt)}
            </span>
          ) : (
            <SkeletonPill label="Loading update time" />
          )}
          <button
            type="button"
            className="ws-btn is-sm"
            onClick={onRefresh}
            disabled={refreshing}
          >
            <RefreshCw className={cn("h-3.5 w-3.5", refreshing && "animate-spin")} />
            {refreshing ? "Refreshing" : "Refresh"}
          </button>
        </>
      }
    />
  );
}
