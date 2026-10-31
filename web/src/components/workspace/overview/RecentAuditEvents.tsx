"use client";

import { useMemo } from "react";
import { ArrowRight, Database } from "lucide-react";
import Link from "next/link";
import { decisionClass, formatRelative, formatTimestamp } from "@/lib/api/format";
import type { AuditResponse } from "@/lib/api/types";
import type { UseLiveDataResult } from "@/lib/hooks/use-live-data";
import { cn } from "@/lib/utils";
import {
  Card,
  CardBody,
  CardHead,
  DecisionBadge,
  EmptyState,
  ErrorState,
  LoadingState,
  SourceBadge,
} from "@/components/workspace/ui";

export function RecentAuditEvents({
  audit,
}: {
  audit: UseLiveDataResult<AuditResponse>;
}) {
  const recentAudit = useMemo(() => (audit.data?.entries ?? []).slice(0, 8), [audit.data]);

  return (
    <Card>
      <CardHead
        title="Recent audit events"
        subtitle="Newest first · latest 12 records · append-only JSONL trail"
        icon={Database}
        actions={
          <Link href="/workspace/audit" className="ws-link">
            Full audit <ArrowRight className="h-3 w-3" />
          </Link>
        }
      />
      <CardBody flush>
        {audit.isLoading ? (
          <LoadingState rows={2} />
        ) : audit.data ? (
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
                        <td className="is-nowrap ws-ink-soft" title={formatTimestamp(entry.ts)}>
                          {formatRelative(entry.ts)}
                        </td>
                        <td>
                          <DecisionBadge decision={entry.decision} short />
                        </td>
                        <td className="font-mono ws-fs-body">{entry.tool}</td>
                        <td>
                          <SourceBadge source={entry.source} />
                        </td>
                        <td className="ws-fs-body">
                          {agent}
                          {session ? (
                            <span className="block font-mono ws-fs-meta ws-ink-faint">
                              {session}
                            </span>
                          ) : null}
                        </td>
                        <td>
                          <Link
                            href={`/workspace/audit?call=${encodeURIComponent(entry.call_id)}`}
                            className={cn(
                              "ws-link font-mono ws-fs-meta",
                              decisionClass(entry.decision),
                            )}
                          >
                            <span title={entry.call_id}>…{entry.call_id.slice(-6)}</span>
                          </Link>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState
              title="No audit entries yet."
              description={
                <>
                  Send a call through <code className="ws-mono">POST /v1/check</code>{" "}
                  from the Activity Monitor to create the first decision record.
                </>
              }
              icon={Database}
            />
          )
        ) : audit.failure ? (
          <div className="p-4">
            <ErrorState failure={audit.failure} onRetry={() => void audit.refresh()} compact />
          </div>
        ) : (
          <div className="p-4">
            <LoadingState rows={2} />
          </div>
        )}
      </CardBody>
    </Card>
  );
}
