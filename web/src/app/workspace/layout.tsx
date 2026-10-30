import type { Metadata } from "next";
import "../workspace.css";
import { WorkspaceShell } from "@/components/workspace/workspace-shell";

export const metadata: Metadata = {
  title: {
    default: "Workspace",
    template: "%s · AgentShield Workspace",
  },
  description:
    "Operate AgentShield: inspect tool-call decisions, approvals, policy, threats, red-team runs, the RAG corpus and audit evidence.",
  robots: {
    index: false,
    follow: false,
  },
};

export default function WorkspaceLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return <WorkspaceShell>{children}</WorkspaceShell>;
}
