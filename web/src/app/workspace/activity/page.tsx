import type { Metadata } from "next";
import { ActivityClient } from "@/components/workspace/activity-client";

export const metadata: Metadata = {
  title: "Activity Monitor",
  description:
    "Inspect live tool-call decisions and send a boundary check through the AgentShield policy decision point.",
};

export default function ActivityPage() {
  return <ActivityClient />;
}
