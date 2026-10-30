import {
  Activity,
  BadgeCheck,
  BarChart3,
  Database,
  FlaskConical,
  Gauge,
  HeartPulse,
  Scale,
  ScrollText,
  Settings2,
  ShieldAlert,
  UserCheck,
  Users,
  Wrench,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";

export type WorkspaceNavItem = {
  href: string;
  label: string;
  description: string;
  icon: LucideIcon;
  exact?: boolean;
  badge?: "pending";
};

export type WorkspaceNavGroup = {
  label: string;
  items: WorkspaceNavItem[];
};

export const workspaceNavGroups: WorkspaceNavGroup[] = [
  {
    label: "Overview",
    items: [
      {
        href: "/workspace",
        label: "Overview",
        description: "Live boundary state and recent decisions",
        icon: Gauge,
        exact: true,
      },
      {
        href: "/workspace/activity",
        label: "Activity Monitor",
        description: "Inspect every audited tool call",
        icon: Activity,
      },
      {
        href: "/workspace/analytics",
        label: "Analytics",
        description: "Decision volume, sources and detector performance",
        icon: BarChart3,
      },
    ],
  },
  {
    label: "Security",
    items: [
      {
        href: "/workspace/agents",
        label: "Agents & Sessions",
        description: "Sessions projected from audit metadata",
        icon: Users,
      },
      {
        href: "/workspace/tools",
        label: "Tools & Permissions",
        description: "Policy tool inventory and observed usage",
        icon: Wrench,
      },
      {
        href: "/workspace/threats",
        label: "Threat Intelligence",
        description: "Real detector findings and investigation",
        icon: ShieldAlert,
      },
      {
        href: "/workspace/approvals",
        label: "Approval Center",
        description: "Single-use human decisions",
        icon: UserCheck,
        badge: "pending",
      },
      {
        href: "/workspace/policy",
        label: "Policy Manager",
        description: "Read-only policy, integrity and evaluation order",
        icon: Scale,
      },
    ],
  },
  {
    label: "Testing",
    items: [
      {
        href: "/workspace/redteam",
        label: "Red Team Lab",
        description: "Isolated ON/OFF enforcement comparison",
        icon: FlaskConical,
      },
      {
        href: "/workspace/corpus",
        label: "RAG Corpus",
        description: "Untrusted retrieval corpus browser",
        icon: Database,
      },
      {
        href: "/workspace/audit",
        label: "Audit & Forensics",
        description: "Append-only decision trail",
        icon: ScrollText,
      },
      {
        href: "/workspace/evidence",
        label: "Security Evidence",
        description: "Historical artifacts and live runtime proof",
        icon: BadgeCheck,
      },
    ],
  },
  {
    label: "System",
    items: [
      {
        href: "/workspace/settings#health",
        label: "Gateway & Health",
        description: "Runtime status, detectors and authorization",
        icon: HeartPulse,
      },
      {
        href: "/workspace/settings#configuration",
        label: "Configuration",
        description: "Environment, limits and configuration actions",
        icon: Settings2,
      },
    ],
  },
];

export const workspaceNavItems = workspaceNavGroups.flatMap((group) => group.items);

export function navItemPath(item: WorkspaceNavItem): string {
  return item.href.split("#")[0];
}

export function navItemHash(item: WorkspaceNavItem): string | null {
  const index = item.href.indexOf("#");
  return index >= 0 ? item.href.slice(index) : null;
}
