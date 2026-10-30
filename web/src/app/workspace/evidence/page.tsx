import type { Metadata } from "next";
import { EvidenceClient } from "@/components/workspace/evidence-client";

export const metadata: Metadata = {
  title: "Security Evidence",
  description:
    "Separate committed historical artifacts from live gateway runtime evidence, with recorded commit and date.",
};

export default function EvidencePage() {
  return <EvidenceClient />;
}
