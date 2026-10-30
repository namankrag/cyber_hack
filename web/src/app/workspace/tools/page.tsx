import type { Metadata } from "next";
import { ToolsClient } from "@/components/workspace/tools-client";

export const metadata: Metadata = {
  title: "Tools & Permissions",
  description:
    "The active policy tool list plus observed audit activity, source allow-lists and approval requirements.",
};

export default function ToolsPage() {
  return <ToolsClient />;
}
