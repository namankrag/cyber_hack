import type { Metadata } from "next";
import { RedteamClient } from "@/components/workspace/redteam-client";

export const metadata: Metadata = {
  title: "Red Team Lab",
  description:
    "Run isolated attack scenarios through the real detector and policy engine, comparing enforcement ON and OFF without changing the global switch.",
};

export default function RedteamPage() {
  return <RedteamClient />;
}
