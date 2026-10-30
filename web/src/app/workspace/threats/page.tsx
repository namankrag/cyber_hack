import type { Metadata } from "next";
import { ThreatsClient } from "@/components/workspace/threats-client";

export const metadata: Metadata = {
  title: "Threat Intelligence",
  description:
    "Detector findings from the audit trail, with inferred presentation categories and explicit severity bases.",
};

export default async function ThreatsPage({
  searchParams,
}: {
  searchParams: Promise<{ event?: string }>;
}) {
  const { event } = await searchParams;
  return <ThreatsClient initialEvent={event ?? null} />;
}
