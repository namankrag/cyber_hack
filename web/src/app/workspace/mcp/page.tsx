import type { Metadata } from "next";
import { McpClient } from "@/components/workspace/mcp-client";

export const metadata: Metadata = {
  title: "MCP Gateway",
  description:
    "Run a real MCP client through AgentShield and watch every tools/call decided at the protocol layer, plus a live check that agents cannot fake trust.",
};

export default function McpPage() {
  return <McpClient />;
}
