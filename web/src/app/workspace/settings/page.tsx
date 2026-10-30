import type { Metadata } from "next";
import { SettingsClient } from "@/components/workspace/settings-client";

export const metadata: Metadata = {
  title: "Gateway & Configuration",
  description:
    "Gateway health, readiness, authorization mode, detector and LLM status, policy integrity and the endpoint map.",
};

export default function SettingsPage() {
  return <SettingsClient />;
}
