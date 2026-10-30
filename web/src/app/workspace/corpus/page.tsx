import type { Metadata } from "next";
import { CorpusClient } from "@/components/workspace/corpus-client";

export const metadata: Metadata = {
  title: "RAG Corpus",
  description:
    "Explore every retrieved document as UNTRUSTED content. Retrieval never confers trust.",
};

export default function CorpusPage() {
  return <CorpusClient />;
}
