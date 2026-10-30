import type { Metadata } from "next";
import { OverviewClient } from "@/components/workspace/overview-client";

export const metadata: Metadata = {
  title: { absolute: "Overview · AgentShield Workspace" },
  description:
    "Live enforcement state, decision volume, threat signals, approvals and recent audit records from the AgentShield gateway.",
};

export default function WorkspaceOverviewPage() {
  return <OverviewClient />;
}
