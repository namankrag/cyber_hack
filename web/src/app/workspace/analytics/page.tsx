import type { Metadata } from "next";
import { AnalyticsClient } from "@/components/workspace/analytics-client";

export const metadata: Metadata = {
  title: "Analytics",
  description:
    "Decision volume, provenance, detector performance and recent audited decisions from the AgentShield gateway.",
};

export default function WorkspaceAnalyticsPage() {
  return <AnalyticsClient />;
}
