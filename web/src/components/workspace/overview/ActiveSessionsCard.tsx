"use client";

import { useMemo } from "react";
import { ArrowRight, Users } from "lucide-react";
import Link from "next/link";
import { formatRelative } from "@/lib/api/format";
import type { AgentsResponse } from "@/lib/api/types";
import type { UseLiveDataResult } from "@/lib/hooks/use-live-data";
import {
  Card,
  CardBody,
  CardHead,
  EmptyState,
  ErrorState,
  LoadingState,
} from "@/components/workspace/ui";

export function ActiveSessionsCard({
  agents,
}: {
  agents: UseLiveDataResult<AgentsResponse>;
}) {
  const topSessions = useMemo(
    () => (agents.data?.sessions ?? []).slice(0, 4),
    [agents.data],
  );

  return (
    <Card>
      <CardHead
        title="Active agent sessions"
        subtitle="Derived from audit metadata keys only · latest records"
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
            <EmptyState
              title="No agent/session metadata observed."
              description="Calls without agent or session metadata are still audited, but cannot be grouped into a session."
              icon={Users}
            />
          )
        ) : agents.failure ? (
          <ErrorState failure={agents.failure} onRetry={() => void agents.refresh()} compact />
        ) : (
          <LoadingState rows={2} />
        )}
      </CardBody>
    </Card>
  );
}
