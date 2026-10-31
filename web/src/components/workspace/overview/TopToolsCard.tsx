"use client";

import { useMemo } from "react";
import { ArrowRight, Bot } from "lucide-react";
import Link from "next/link";
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

export function TopToolsCard({
  metrics,
}: {
  metrics: UseLiveDataResult<MetricsResponse>;
}) {
  const topTools = useMemo(
    () => (metrics.data?.top_tools ?? []).slice(0, 6),
    [metrics.data],
  );

  return (
    <Card>
      <CardHead
        title="Top tools by volume"
        subtitle="Observed calls in the selected window · stacked by decision"
        icon={Bot}
        actions={
          <Link href="/workspace/tools" className="ws-link">
            Tools <ArrowRight className="h-3 w-3" />
          </Link>
        }
      />
      <CardBody>
        {metrics.data ? (
          topTools.length ? (
            <Bars
              rows={topTools.map((tool) => ({
                label: tool.tool,
                value: tool.total,
                note: `${tool.total} · ${tool.deny} deny`,
                segments: [
                  { value: tool.allow, tone: "allow" as const },
                  { value: tool.require_approval, tone: "hold" as const },
                  { value: tool.deny, tone: "deny" as const },
                ],
              }))}
            />
          ) : (
            <EmptyState
              title="No tool calls in this window."
              description="Calls recorded by the gateway in the selected window appear here."
              icon={Bot}
            />
          )
        ) : metrics.failure ? (
          <ErrorState failure={metrics.failure} onRetry={() => void metrics.refresh()} compact />
        ) : (
          <LoadingState rows={2} />
        )}
      </CardBody>
    </Card>
  );
}
