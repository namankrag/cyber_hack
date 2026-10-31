import type { Metadata } from "next";
import { GeistMono } from "geist/font/mono";
import { GeistSans } from "geist/font/sans";
import "./tokens.css";
import "./globals.css";

export const metadata: Metadata = {
  title: {
    default: "AgentShield — Secure the agent, not just the prompt",
    template: "%s · AgentShield",
  },
  description:
    "AgentShield is the policy enforcement layer between AI agents and their tools. Every tool call is inspected, verified and decided: ALLOW, DENY or REQUIRE_APPROVAL.",
  icons: {
    icon: [{ url: "/shield.svg", type: "image/svg+xml" }],
  },
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" className={`${GeistSans.variable} ${GeistMono.variable}`}>
      <body>{children}</body>
    </html>
  );
}
