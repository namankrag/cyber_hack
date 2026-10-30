import type { Metadata } from "next";
import { PolicyClient } from "@/components/workspace/policy-client";

export const metadata: Metadata = {
  title: "Policy Manager",
  description:
    "Read-only view of the active policy, its defaults, tool rules, evaluation order and integrity digest.",
};

export default function PolicyPage() {
  return <PolicyClient />;
}
