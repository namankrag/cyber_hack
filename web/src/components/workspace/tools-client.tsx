"use client";

import {
  AlertTriangle,
  Ban,
  FilterX,
  LockKeyhole,
  RefreshCw,
  Search,
  ShieldCheck,
  UserCheck,
  Wrench,
} from "lucide-react";
import { useMemo, useState } from "react";
import { formatNumber, formatRelative, sourceLabel, titleCase } from "@/lib/api/format";
import type { ToolView, ToolsResponse } from "@/lib/api/types";
import { useLiveData } from "@/lib/hooks/use-live-data";
import { cn } from "@/lib/utils";
import {
  Banner,
  Card,
  CardBody,
  CardHead,
  DecisionBadge,
  EmptyState,
  ErrorState,
  LiveMeta,
  LoadingState,
  PageHeader,
  SourceBadge,
  StatCard,
  StatusBadge,
} from "@/components/workspace/ui";

const requirementLabels: Record<string, string> = {
  deny: "Denied outright",
  require_approval: "Human approval",
  source_scoped: "Source-scoped",
  escalated: "Sensitivity escalation",
  policy: "Policy allow",
  unknown_tool: "Unknown tool",
};

const requirementTone = (requirement: string) => {
  if (requirement === "deny") return "is-deny";
  if (requirement === "require_approval") return "is-hold";
  if (requirement === "unknown_tool") return "is-purple";
  if (requirement === "source_scoped" || requirement === "escalated") return "is-warn";
  return "is-allow";
};

const requirements = [
  "all",
  "deny",
  "require_approval",
  "source_scoped",
  "escalated",
  "policy",
  "unknown_tool",
] as const;

const sensitivities = ["all", "low", "high", "unknown"] as const;

export function ToolsClient() {
  const [search, setSearch] = useState("");
  const [requirement, setRequirement] =
    useState<(typeof requirements)[number]>("all");
  const [sensitivity, setSensitivity] =
    useState<(typeof sensitivities)[number]>("all");
  const [observedOnly, setObservedOnly] = useState(false);

  const tools = useLiveData<ToolsResponse>("/v1/tools?limit=500", {
    intervalMs: 20_000,
  });

  const rows = useMemo(() => tools.data?.tools ?? [], [tools.data]);

  const filtered = useMemo(() => {
    const term = search.trim().toLowerCase();
    return rows.filter((tool) => {
      if (requirement !== "all" && tool.decision_requirement !== requirement) {
        return false;
      }
      if (sensitivity !== "all" && tool.sensitivity !== sensitivity) return false;
      if (observedOnly && tool.activity.calls === 0) return false;
      if (!term) return true;
      return [
        tool.name,
        tool.sensitivity,
        tool.decision_requirement,
        ...tool.allow_sources,
        ...tool.activity.sources,
      ]
        .join(" ")
        .toLowerCase()
        .includes(term);
    });
  }, [observedOnly, requirement, rows, search, sensitivity]);

  const observed = rows.filter((tool) => tool.activity.calls > 0);
  const unknown = rows.filter((tool) => tool.decision_requirement === "unknown_tool");
  const approvalTools = rows.filter(
    (tool) => tool.decision_requirement === "require_approval",
  );
  const activeFilters =
    search.trim().length > 0 ||
    requirement !== "all" ||
    sensitivity !== "all" ||
    observedOnly;

  const clearFilters = () => {
    setSearch("");
    setRequirement("all");
    setSensitivity("all");
    setObservedOnly(false);
  };

  return (
    <div className="ws-stack">
      <PageHeader
        eyebrow="Tools & permissions"
        title={
          <>
            What the agent <em>may touch.</em>
          </>
        }
        description="The authoritative tool list is the active policy, joined with observed audit activity. Source allow-lists, approval requirements and unknown-tool fail-closed paths are shown exactly as the gateway reports them."
        actions={
          <button
            type="button"
            className="ws-btn is-sm"
            onClick={() => void tools.refresh()}
            disabled={tools.isRefreshing}
          >
            <RefreshCw
              className={cn("h-3.5 w-3.5", tools.isRefreshing && "animate-spin")}
            />
            {tools.isRefreshing ? "Refreshing" : "Refresh"}
          </button>
        }
      />

      {tools.failure && tools.data ? (
        <Banner tone="warn" icon={AlertTriangle}>
          <strong>Live updates interrupted.</strong> Showing the last successful tool
          snapshot. {tools.failure.message}
        </Banner>
      ) : null}

      <div className="ws-grid ws-grid-4">
        <StatCard
          label="Policy tools"
          value={tools.data ? formatNumber(tools.data.policy_tool_count) : "—"}
          meta="Declared in the active policy"
          icon={Wrench}
        />
        <StatCard
          label="Observed in audit"
          value={tools.data ? formatNumber(observed.length) : "—"}
          meta="At least one real call"
          icon={ShieldCheck}
          tone="lime"
        />
        <StatCard
          label="Require approval"
          value={tools.data ? formatNumber(approvalTools.length) : "—"}
          meta="Always route to a human"
          icon={UserCheck}
          tone="purple"
        />
        <StatCard
          label="Unknown tools"
          value={tools.data ? formatNumber(unknown.length) : "—"}
          meta="Observed but absent from policy"
          icon={Ban}
        />
      </div>

      <Card>
        <CardHead
          title="Tool inventory"
          subtitle="Active policy joined with the most recent 500 audit entries"
          icon={Wrench}
          actions={
            tools.lastUpdated ? (
              <LiveMeta
                lastUpdated={tools.lastUpdated}
                isRefreshing={tools.isRefreshing}
                isStale={tools.isStale}
                intervalLabel="20s"
              />
            ) : null
          }
        />
        <div className="ws-filter-bar">
          <label className="ws-field">
            <span className="ws-label">Search</span>
            <span className="ws-search">
              <Search className="h-3.5 w-3.5" />
              <input
                className="ws-input"
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="Tool, source or requirement"
                aria-label="Search tools"
              />
            </span>
          </label>
          <label className="ws-field">
            <span className="ws-label">Requirement</span>
            <select
              className="ws-select"
              value={requirement}
              onChange={(event) =>
                setRequirement(event.target.value as (typeof requirements)[number])
              }
            >
              {requirements.map((value) => (
                <option key={value} value={value}>
                  {value === "all" ? "All requirements" : requirementLabels[value]}
                </option>
              ))}
            </select>
          </label>
          <label className="ws-field">
            <span className="ws-label">Sensitivity</span>
            <select
              className="ws-select"
              value={sensitivity}
              onChange={(event) =>
                setSensitivity(event.target.value as (typeof sensitivities)[number])
              }
            >
              {sensitivities.map((value) => (
                <option key={value} value={value}>
                  {value === "all" ? "All sensitivities" : titleCase(value)}
                </option>
              ))}
            </select>
          </label>
          <label className="ws-check">
            <input
              type="checkbox"
              checked={observedOnly}
              onChange={(event) => setObservedOnly(event.target.checked)}
            />
            Observed only
          </label>
          <span className="ws-count-pill">
            {filtered.length} / {rows.length}
          </span>
          {activeFilters ? (
            <button type="button" className="ws-btn is-xs is-ghost" onClick={clearFilters}>
              <FilterX className="h-3 w-3" /> Clear
            </button>
          ) : null}
        </div>

        <CardBody>
          {tools.isLoading ? (
            <LoadingState rows={3} />
          ) : tools.failure && !tools.data ? (
            <ErrorState failure={tools.failure} onRetry={tools.refresh} />
          ) : filtered.length ? (
            <div className="ws-grid ws-grid-2">
              {filtered.map((tool) => (
                <ToolCard key={tool.name} tool={tool} />
              ))}
            </div>
          ) : rows.length ? (
            <EmptyState
              title="No tools match these filters."
              description="Clear the filters or include tools with no observed activity."
              icon={FilterX}
              action={
                <button type="button" className="ws-btn is-sm" onClick={clearFilters}>
                  Clear filters
                </button>
              }
            />
          ) : (
            <EmptyState
              title="No tools returned."
              description="The active policy may be empty. The gateway still fails closed for unknown tools."
              icon={Wrench}
            />
          )}
        </CardBody>
      </Card>

      <Banner tone="purple" icon={LockKeyhole}>
        <strong>Read-only in this build.</strong> There is no policy publish endpoint,
        so this page never offers an edit control. Tool permissions change only by
        updating the policy file on the gateway host and restarting or reloading it
        through your deployment process. {tools.data?.notes.discovery ?? ""}
      </Banner>
    </div>
  );
}

function ToolCard({ tool }: { tool: ToolView }) {
  const unknown = tool.decision_requirement === "unknown_tool";
  const activity = tool.activity;
  const lastDecision = activity.last_decision;

  return (
    <div className={cn("ws-tool-card", unknown && "is-unknown")}>
      <div className="ws-tool-head">
        <div className="min-w-0">
          <div className="ws-tool-name">{tool.name}</div>
          <div className="ws-wrap mt-1.5">
            <span
              className={cn("ws-badge", requirementTone(tool.decision_requirement))}
            >
              {requirementLabels[tool.decision_requirement] ?? tool.decision_requirement}
            </span>
            {tool.sensitivity !== "unknown" ? (
              <span className="ws-badge is-neutral">
                {tool.sensitivity} sensitivity
              </span>
            ) : (
              <span className="ws-badge is-purple">not in policy</span>
            )}
            {tool.enabled === false ? (
              <StatusBadge tone="error">disabled</StatusBadge>
            ) : tool.enabled === true ? (
              <StatusBadge tone="ok">enabled</StatusBadge>
            ) : (
              <StatusBadge tone="neutral">unknown</StatusBadge>
            )}
            {tool.require_approval === true ? (
              <StatusBadge tone="warn">approval required</StatusBadge>
            ) : null}
          </div>
        </div>
        {lastDecision ? <DecisionBadge decision={lastDecision} short /> : null}
      </div>

      <div className="ws-tool-stats">
        <span className="ws-mini-stat">
          <strong>{formatNumber(activity.calls)}</strong> calls
        </span>
        <span className="ws-mini-stat">
          <strong>{formatNumber(activity.allow)}</strong> allow
        </span>
        <span className="ws-mini-stat">
          <strong>{formatNumber(activity.require_approval)}</strong> hold
        </span>
        <span className="ws-mini-stat">
          <strong>{formatNumber(activity.deny)}</strong> deny
        </span>
      </div>

      <div className="ws-stack-sm">
        <div>
          <span className="ws-label">Allowed sources</span>
          <div className="ws-wrap mt-1.5">
            {tool.allow_sources.length ? (
              tool.allow_sources.map((source) => (
                <SourceBadge key={source} source={source} />
              ))
            ) : (
              <span className="ws-hint">
                No source allow-list — governed by sensitivity and approval rules.
              </span>
            )}
          </div>
        </div>
        <div className="ws-between text-[10.5px] text-[#6f6c66]">
          <span>
            On disallowed source:{" "}
            <strong className="text-[#171717]">
              {tool.on_disallowed_source
                ? requirementLabels[tool.on_disallowed_source] ??
                  titleCase(tool.on_disallowed_source)
                : "n/a"}
            </strong>
          </span>
          <span>{activity.last_seen ? formatRelative(activity.last_seen) : "never observed"}</span>
        </div>
        {activity.sources.length ? (
          <div className="ws-wrap">
            <span className="ws-label">Observed provenance</span>
            {activity.sources.map((source) => (
              <span key={source} className="ws-mini-stat">
                {sourceLabel(source)}
              </span>
            ))}
          </div>
        ) : null}
      </div>
    </div>
  );
}
