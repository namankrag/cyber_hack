import type { Metadata } from "next";
import { AgentsClient } from "@/components/workspace/agents-client";

export const metadata: Metadata = {
  title: "Agents & Sessions",
  description:
    "Agent and session groupings derived from audit metadata, with decision counts, tools and provenance.",
};

export default async function AgentsPage({
  searchParams,
}: {
  searchParams: Promise<{ session?: string }>;
}) {
  const { session } = await searchParams;
  return <AgentsClient initialSession={session ?? null} />;
}
