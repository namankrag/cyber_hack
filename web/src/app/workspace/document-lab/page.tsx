import type { Metadata } from "next";
import { DocumentLabClient } from "@/components/workspace/document-lab-client";

export const metadata: Metadata = {
  title: "Document Lab",
  description:
    "Upload a document and watch AgentShield decide every action it tries to trigger, then PatchProof prove, patch and verify the code those attacks targeted.",
};

export default function DocumentLabPage() {
  return <DocumentLabClient />;
}
