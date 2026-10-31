"use client";

import {
  AlertTriangle,
  Clock3,
  Database,
  FileSearch,
  FilterX,
  History,
  RefreshCw,
  Search,
  ShieldAlert,
  UserCheck,
} from "lucide-react";
import Link from "next/link";
import { useMemo, useState } from "react";
import {
  formatNumber,
  formatRelative,
  formatTimestamp,
  toEpochMs,
} from "@/lib/api/format";
import type { ApprovalsResponse, AuditEntry, AuditResponse } from "@/lib/api/types";
import { useLiveData } from "@/lib/hooks/use-live-data";
import { cn } from "@/lib/utils";
import { CopyButton } from "@/components/workspace/copy-button";
import { JsonBlock } from "@/components/workspace/json-block";
import {
  Banner,
  Card,
  CardBody,
  CardHead,
  DecisionBadge,
  DetectionList,
  EmptyState,
  ErrorState,
  KeyValue,
  LoadingState,
  PageHeader,
  ReasonList,
  SourceBadge,
  StatCard,
  StatusBadge,
} from "@/components/workspace/ui";

const limits = [50, 100, 250, 500] as const;
const decisions = ["all", "allow", "require_approval", "deny"] as const;
const ranges = [
  { value: "1h", label: "Last hour", ms: 3_600_000 },
  { value: "24h", label: "Last 24 hours", ms: 86_400_000 },
  { value: "7d", label: "Last 7 days", ms: 7 * 86_400_000 },
  { value: "all", label: "All retained", ms: null },
] as const;
type RangeKey = (typeof ranges)[number]["value"];

export function AuditClient({ initialCall }: { initialCall: string | null }) {
  const [limit, setLimit] = useState<number>(250);
  const [decision, setDecision] = useState<(typeof decisions)[number]>("all");
  const [range, setRange] = useState<RangeKey>("24h");
  const [search, setSearch] = useState(initialCall ?? "");
  const [tab, setTab] = useState<"trail" | "approvals">("trail");
  const [selectedCall, setSelectedCall] = useState<string | null>(initialCall);

  const audit = useLiveData<AuditResponse>(`/v1/audit?limit=${limit}`, {
    intervalMs: 10_000,
  });
  const approvals = useLiveData<ApprovalsResponse>("/v1/approvals?limit=500", {
    intervalMs: 20_000,
  });

  const entries = useMemo(() => audit.data?.entries ?? [], [audit.data]);
  const recentApprovals = useMemo(() => approvals.data?.recent ?? [], [approvals.data]);

  const filtered = useMemo(() => {
    const term = search.trim().toLowerCase();
    const rangeMs = ranges.find((item) => item.value === range)?.ms ?? null;
    // Anchor relative ranges to the last successful audit refresh instead of
    // reading the clock during render.
    const cutoff =
      rangeMs === null || audit.lastUpdated === null
        ? null
        : audit.lastUpdated - rangeMs;

    return entries.filter((entry) => {
      if (decision !== "all" && entry.decision !== decision) return false;
      if (cutoff !== null) {
        const ts = toEpochMs(entry.ts);
        if (ts === null || ts < cutoff) return false;
      }
      if (!term) return true;
      const metadata = entry.metadata ?? {};
      return [
        entry.call_id,
        entry.tool,
        entry.source,
        entry.decision,
        String(metadata.agent ?? metadata.agent_id ?? ""),
        String(metadata.session_id ?? metadata.session ?? metadata.thread_id ?? ""),
        ...(entry.reasons ?? []).map((reason) => `${reason.rule} ${reason.detail}`),
        JSON.stringify(entry.arguments ?? {}),
      ]
        .join(" ")
        .toLowerCase()
        .includes(term);
    });
  }, [audit.lastUpdated, decision, entries, range, search]);

  const selected =
    entries.find((entry) => entry.call_id === selectedCall) ??
    recentApprovals.find((entry) => entry.call_id === selectedCall) ??
    filtered[0] ??
    null;

  const activeFilters =
    decision !== "all" || range !== "24h" || search.trim().length > 0;

  const clearFilters = () => {
    setDecision("all");
    setRange("24h");
    setSearch("");
  };

  const refreshAll = () => {
    void Promise.all([audit.refresh(), approvals.refresh()]);
  };

  const held = entries.filter(
    (entry) => entry.decision === "require_approval" && !entry.approval,
  ).length;

  return (
    <div className="ws-stack">
      <PageHeader
        eyebrow="Audit & forensics"
        title={
          <>
            The record, <em>unmodified.</em>
          </>
        }
        description="Search the append-only JSONL decision trail, inspect full records and review the approval chain. Filters are applied in the browser to the audit sample returned by the gateway; the trail itself is never rewritten here."
        actions={
          <button
            type="button"
            className="ws-btn is-sm"
            onClick={refreshAll}
            disabled={audit.isRefreshing || approvals.isRefreshing}
          >
            <RefreshCw
              className={cn(
                "h-3.5 w-3.5",
                (audit.isRefreshing || approvals.isRefreshing) && "animate-spin",
              )}
            />
            {audit.isRefreshing || approvals.isRefreshing ? "Refreshing" : "Refresh"}
          </button>
        }
      />

      {audit.failure && audit.data ? (
        <Banner tone="warn" icon={AlertTriangle}>
          <strong>Live updates interrupted.</strong> Showing the last successful audit
          snapshot. {audit.failure.message}
        </Banner>
      ) : null}

      <div className="ws-grid ws-grid-4">
        <StatCard
          label="Entries in sample"
          value={audit.data ? formatNumber(entries.length) : "—"}
          meta={audit.data ? `limit ${limit} · newest first` : audit.failure ? "Gateway unreachable \u2014 retry" : "Loading\u2026"}
          icon={Database}
        />
        <StatCard
          label="Held, no decision"
          value={audit.data ? formatNumber(held) : "—"}
          meta="May still be waiting for a human"
          icon={UserCheck}
          tone="purple"
        />
        <StatCard
          label="Human decisions"
          value={approvals.data ? formatNumber(recentApprovals.length) : "—"}
          meta="Append-only approval entries"
          icon={History}
        />
        <StatCard
          label="Pending queue"
          value={approvals.data ? formatNumber(approvals.data.summary.pending) : "—"}
          meta="Live from the approval queue"
          icon={Clock3}
        />
      </div>

      <div className="ws-grid ws-grid-sidebar">
        <Card>
          <div className="ws-tabs">
            <button
              type="button"
              className={cn("ws-tab", tab === "trail" && "is-active")}
              onClick={() => setTab("trail")}
              aria-pressed={tab === "trail"}
            >
              Decision trail
            </button>
            <button
              type="button"
              className={cn("ws-tab", tab === "approvals" && "is-active")}
              onClick={() => setTab("approvals")}
              aria-pressed={tab === "approvals"}
            >
              Approval chain
            </button>
          </div>

          {tab === "trail" ? (
            <>
              <div className="ws-filter-bar">
                <label className="ws-field">
                  <span className="ws-label">Search</span>
                  <span className="ws-search">
                    <Search className="h-3.5 w-3.5" />
                    <input
                      className="ws-input"
                      value={search}
                      onChange={(event) => setSearch(event.target.value)}
                      placeholder="Call ID, tool, agent, reason, argument"
                      aria-label="Search audit entries"
                    />
                  </span>
                </label>
                <label className="ws-field">
                  <span className="ws-label">Decision</span>
                  <select
                    className="ws-select"
                    value={decision}
                    onChange={(event) =>
                      setDecision(event.target.value as (typeof decisions)[number])
                    }
                  >
                    {decisions.map((value) => (
                      <option key={value} value={value}>
                        {value === "all"
                          ? "All decisions"
                          : value === "require_approval"
                            ? "Approval"
                            : value}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="ws-field">
                  <span className="ws-label">Time range</span>
                  <select
                    className="ws-select"
                    value={range}
                    onChange={(event) => setRange(event.target.value as RangeKey)}
                  >
                    {ranges.map((item) => (
                      <option key={item.value} value={item.value}>
                        {item.label}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="ws-field">
                  <span className="ws-label">Limit</span>
                  <select
                    className="ws-select"
                    value={limit}
                    onChange={(event) => setLimit(Number(event.target.value))}
                  >
                    {limits.map((value) => (
                      <option key={value} value={value}>
                        {value} entries
                      </option>
                    ))}
                  </select>
                </label>
                <span className="ws-count-pill">
                  {filtered.length} / {entries.length}
                </span>
                {activeFilters ? (
                  <button
                    type="button"
                    className="ws-btn is-xs is-ghost"
                    onClick={clearFilters}
                  >
                    <FilterX className="h-3 w-3" /> Clear
                  </button>
                ) : null}
                <CopyButton
                  value={JSON.stringify(filtered, null, 2)}
                  label="Copy filtered"
                />
              </div>

              {audit.isLoading ? (
                <CardBody>
                  <LoadingState rows={3} />
                </CardBody>
              ) : audit.failure && !audit.data ? (
                <CardBody>
                  <ErrorState failure={audit.failure} onRetry={refreshAll} />
                </CardBody>
              ) : filtered.length ? (
                <div className="ws-table-wrap">
                  <table className="ws-table">
                    <thead>
                      <tr>
                        <th>Time</th>
                        <th>Decision</th>
                        <th>Tool</th>
                        <th>Source</th>
                        <th>Agent / session</th>
                        <th>Approval</th>
                        <th>Call ID</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filtered.map((entry) => {
                        const metadata = entry.metadata ?? {};
                        const agent =
                          String(metadata.agent ?? metadata.agent_id ?? "") || "—";
                        const session =
                          String(
                            metadata.session_id ??
                              metadata.session ??
                              metadata.thread_id ??
                              "",
                          ) || "";
                        return (
                          <tr
                            key={`${entry.call_id}-${String(entry.ts)}`}
                            className={cn(
                              "is-clickable",
                              selected?.call_id === entry.call_id && "is-selected",
                            )}
                            onClick={() => setSelectedCall(entry.call_id)}
                            tabIndex={0}
                            onKeyDown={(event) => {
                              if (event.key === "Enter" || event.key === " ") {
                                event.preventDefault();
                                setSelectedCall(entry.call_id);
                              }
                            }}
                          >
                            <td className="is-nowrap ws-fs-body ws-ink-soft">
                              {formatTimestamp(entry.ts)}
                            </td>
                            <td>
                              <DecisionBadge decision={entry.decision} short />
                            </td>
                            <td className="font-mono ws-fs-body">{entry.tool}</td>
                            <td>
                              <SourceBadge source={entry.source} />
                            </td>
                            <td className="ws-fs-body">
                              {agent}
                              {session ? (
                                <span className="block font-mono ws-fs-meta ws-ink-faint">
                                  {session}
                                </span>
                              ) : null}
                            </td>
                            <td className="ws-fs-meta">
                              {entry.approval ? (
                                <StatusBadge
                                  tone={entry.approval === "deny" ? "error" : "ok"}
                                >
                                  {entry.approval}
                                </StatusBadge>
                              ) : entry.decision === "require_approval" ? (
                                <StatusBadge tone="warn">awaiting</StatusBadge>
                              ) : (
                                <span className="ws-ink-faint">—</span>
                              )}
                            </td>
                            <td className="font-mono ws-fs-meta">{entry.call_id}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              ) : entries.length ? (
                <EmptyState
                  title="No records match these filters."
                  description="Widen the time range, change the decision filter or clear the search."
                  icon={FilterX}
                  action={
                    <button type="button" className="ws-btn is-sm" onClick={clearFilters}>
                      Clear filters
                    </button>
                  }
                />
              ) : (
                <EmptyState
                  title="No audit entries in this sample."
                  description="The trail is empty for the selected limit. Send a boundary check or run a scenario to create records."
                  icon={Database}
                />
              )}
            </>
          ) : (
            <>
              <div className="ws-filter-bar">
                <span className="ws-count-pill">
                  {recentApprovals.length} recent decisions
                </span>
                <span className="ws-count-pill">
                  pending {approvals.data?.summary.pending ?? 0}
                </span>
                <span className="ws-count-pill">
                  approved {approvals.data?.summary.approved ?? 0}
                </span>
                <span className="ws-count-pill">
                  rejected {approvals.data?.summary.rejected ?? 0}
                </span>
                <span className="ws-count-pill">
                  consumed {approvals.data?.summary.consumed ?? 0}
                </span>
              </div>
              {approvals.isLoading ? (
                <CardBody>
                  <LoadingState rows={3} />
                </CardBody>
              ) : approvals.failure && !approvals.data ? (
                <CardBody>
                  <ErrorState failure={approvals.failure} onRetry={refreshAll} />
                </CardBody>
              ) : recentApprovals.length ? (
                <div className="ws-table-wrap">
                  <table className="ws-table">
                    <thead>
                      <tr>
                        <th>Time</th>
                        <th>Verdict</th>
                        <th>Tool</th>
                        <th>Approval of</th>
                        <th>Args hash</th>
                        <th>Consumed by</th>
                        <th>Entry call ID</th>
                      </tr>
                    </thead>
                    <tbody>
                      {recentApprovals.map((entry) => (
                        <tr
                          key={`${entry.call_id}-${String(entry.ts)}`}
                          className={cn(
                            "is-clickable",
                            selected?.call_id === entry.call_id && "is-selected",
                          )}
                          onClick={() => setSelectedCall(entry.call_id)}
                          tabIndex={0}
                          onKeyDown={(event) => {
                            if (event.key === "Enter" || event.key === " ") {
                              event.preventDefault();
                              setSelectedCall(entry.call_id);
                            }
                          }}
                        >
                          <td className="is-nowrap ws-fs-body ws-ink-soft">
                            {formatTimestamp(entry.ts)}
                          </td>
                          <td>
                            {entry.approval === "approve" ? (
                              <StatusBadge tone="ok">approved</StatusBadge>
                            ) : entry.approval === "deny" ? (
                              <StatusBadge tone="error">rejected</StatusBadge>
                            ) : (
                              <StatusBadge tone="neutral">consumed</StatusBadge>
                            )}
                          </td>
                          <td className="font-mono ws-fs-body">{entry.tool}</td>
                          <td className="font-mono ws-fs-meta">
                            {entry.approval_of ?? "—"}
                          </td>
                          <td className="font-mono ws-fs-meta">
                            {entry.args_hash ?? "—"}
                          </td>
                          <td className="font-mono ws-fs-meta">
                            {entry.consumed_by ?? "—"}
                          </td>
                          <td className="font-mono ws-fs-meta">{entry.call_id}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <EmptyState
                  title="No approval entries recorded."
                  description="Human approve, reject and consume entries appear here after the gateway appends them."
                  icon={History}
                  action={
                    <Link href="/workspace/approvals" className="ws-btn is-sm">
                      Open Approval Center
                    </Link>
                  }
                />
              )}
            </>
          )}
        </Card>

        <div className="ws-detail">
          <Card>
            <CardHead
              title="Forensic inspector"
              subtitle="Complete record, reasons, detectors and approval chain fields"
              icon={FileSearch}
              actions={
                selected ? (
                  <CopyButton
                    value={JSON.stringify(selected, null, 2)}
                    label="Copy JSON"
                  />
                ) : null
              }
            />
            <CardBody>
              {selected ? (
                <AuditForensics entry={selected} />
              ) : (
                <EmptyState
                  title="Select a record."
                  description="Choose a decision or approval entry to inspect the complete append-only record."
                  icon={FileSearch}
                />
              )}
            </CardBody>
          </Card>
        </div>
      </div>

      <Banner tone="purple" icon={Database}>
        <strong>Forensic limits.</strong> This view reads the last {limit} audit
        entries returned by the gateway. Rotation and retention are operator-owned; the
        console cannot retrieve records the gateway no longer holds. Approval entries
        are immutable history, not current authorization.
      </Banner>
    </div>
  );
}

function AuditForensics({ entry }: { entry: AuditEntry }) {
  const metadata = entry.metadata ?? {};
  const agent = String(metadata.agent ?? metadata.agent_id ?? "") || "—";
  const session =
    String(metadata.session_id ?? metadata.session ?? metadata.thread_id ?? "") || "—";

  return (
    <div className="ws-stack">
      <div className="ws-between">
        <DecisionBadge decision={entry.decision} />
        <SourceBadge source={entry.source} />
      </div>
      <KeyValue
        items={[
          { label: "Tool", value: entry.tool, mono: true },
          { label: "Call ID", value: entry.call_id, mono: true },
          { label: "Time", value: formatTimestamp(entry.ts) },
          { label: "Age", value: formatRelative(entry.ts) },
          { label: "Agent", value: agent },
          { label: "Session", value: session, mono: true },
          {
            label: "Fail closed",
            value: entry.fail_closed ? (
              <StatusBadge tone="warn">yes</StatusBadge>
            ) : (
              <StatusBadge tone="ok">no</StatusBadge>
            ),
          },
          ...(entry.approval
            ? [{ label: "Approval", value: entry.approval }]
            : []),
          ...(entry.approval_of
            ? [{ label: "Approval of", value: entry.approval_of, mono: true }]
            : []),
          ...(entry.args_hash
            ? [{ label: "Args hash", value: entry.args_hash, mono: true }]
            : []),
          ...(entry.consumed_by
            ? [{ label: "Consumed by", value: entry.consumed_by, mono: true }]
            : []),
        ]}
      />
      {entry.decision === "require_approval" && !entry.approval ? (
        <Banner tone="warn" icon={ShieldAlert}>
          This call was held by policy. If it is still pending, decide it in the
          Approval Center. The audit record alone does not authorize execution.
        </Banner>
      ) : null}
      <div>
        <span className="ws-label">Policy reasons</span>
        <ReasonList reasons={entry.reasons ?? []} />
      </div>
      <div>
        <span className="ws-label">Detector output</span>
        <DetectionList detections={entry.detections ?? []} compact />
      </div>
      <JsonBlock value={entry.arguments ?? {}} title="Arguments" collapsedLines={10} />
      {Object.keys(metadata).length ? (
        <JsonBlock value={metadata} title="Metadata" collapsedLines={8} />
      ) : null}
      <JsonBlock value={entry} title="Full audit record" collapsedLines={14} />
      {entry.decision === "require_approval" && !entry.approval ? (
        <Link href="/workspace/approvals" className="ws-link">
          Review in Approval Center
        </Link>
      ) : null}
    </div>
  );
}
