import type { Metadata } from "next";
import { AuditClient } from "@/components/workspace/audit-client";

export const metadata: Metadata = {
  title: "Audit & Forensics",
  description:
    "Search the append-only decision trail, inspect full records and review the approval chain.",
};

export default async function AuditPage({
  searchParams,
}: {
  searchParams: Promise<{ call?: string }>;
}) {
  const { call } = await searchParams;
  return <AuditClient initialCall={call ?? null} />;
}
