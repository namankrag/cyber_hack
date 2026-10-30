import type { Metadata } from "next";
import { ApprovalsClient } from "@/components/workspace/approvals-client";

export const metadata: Metadata = {
  title: "Approval Center",
  description:
    "Review calls held by policy. Human decisions are single-use and bound to the exact argument hash.",
};

export default function ApprovalsPage() {
  return <ApprovalsClient />;
}
