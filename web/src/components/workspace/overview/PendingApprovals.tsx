"use client";

import { useMemo } from "react";
import { ArrowRight, BadgeCheck, UserCheck } from "lucide-react";
import Link from "next/link";
import { formatNumber, formatRelative } from "@/lib/api/format";
import type { ApprovalsResponse } from "@/lib/api/types";
import type { UseLiveDataResult } from "@/lib/hooks/use-live-data";
import {
  Card,
  CardBody,
  CardHead,
  EmptyState,
  ErrorState,
  LoadingState,
} from "@/components/workspace/ui";

export function PendingApprovals({
  approvals,
}: {
  approvals: UseLiveDataResult<ApprovalsResponse>;
}) {
  const pendingList = useMemo(
    () => (approvals.data?.pending ?? []).slice(0, 5),
    [approvals.data],
  );
  const pendingTotal = approvals.data?.summary.pending ?? 0;

  return (
    <Card>
      <CardHead
        title={`Pending human decisions${approvals.data && pendingTotal > 0 ? ` · ${formatNumber(pendingTotal)}` : ""}`}
        subtitle="Single-use, argument-hash-bound approvals · latest records"
        icon={UserCheck}
        actions={
          <Link href="/workspace/approvals" className="ws-link">
            Approval Center <ArrowRight className="h-3 w-3" />
          </Link>
        }
      />
      <CardBody>
        {approvals.data ? (
          pendingList.length ? (
            <div className="ws-stack-sm">
              {pendingList.map((entry) => (
                <div key={entry.call_id} className="ws-list-card">
                  <div className="ws-between">
                    <span className="font-mono ws-fs-meta font-semibold">
                      {entry.tool}
                    </span>
                    <span className="ws-badge is-hold">pending</span>
                  </div>
                  <p className="mt-1 line-clamp-2 ws-fs-body leading-relaxed ws-ink-soft">
                    {entry.reasons[0]?.detail ?? "Held by policy."}
                  </p>
                  <div className="mt-1.5 flex items-center justify-between ws-fs-meta ws-ink-faint">
                    <span className="font-mono">{entry.call_id}</span>
                    <span>{formatRelative(entry.ts)}</span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <EmptyState
              title="No calls are waiting for a human."
              description="The approval queue is clear in the current audit window."
              icon={BadgeCheck}
            />
          )
        ) : approvals.failure ? (
          <ErrorState failure={approvals.failure} onRetry={() => void approvals.refresh()} compact />
        ) : (
          <LoadingState rows={2} />
        )}
      </CardBody>
    </Card>
  );
}
