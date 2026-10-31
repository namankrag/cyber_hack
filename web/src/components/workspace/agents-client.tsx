"use client";

import {
  Activity,
  Bot,
  Clock3,
  FilterX,
  RefreshCw,
  Search,
  ShieldAlert,
  UserCheck,
  Users,
} from "lucide-react";
import { useMemo, useState } from "react";
import {
  formatNumber,
  formatRelative,
  formatTimestamp,
} from "@/lib/api/format";
import type { AgentsResponse, AgentSession } from "@/lib/api/types";
import { useLiveData } from "@/lib/hooks/use-live-data";
import { cn } from "@/lib/utils";
import { CopyButton } from "@/components/workspace/copy-button";
import {
  Banner,
  Card,
  CardBody,
  CardHead,
  Distribution,
  EmptyState,
  ErrorState,
  KeyValue,
  LiveMeta,
  LoadingState,
  PageHeader,
  SourceBadge,
  StatCard,
  StatusBadge,
} from "@/components/workspace/ui";

const sortOptions = [
  { value: "recent", label: "Most recent" },
  { value: "calls", label: "Most calls" },
  { value: "deny", label: "Most denied" },
  { value: "held", label: "Most held" },
] as const;

type SortKey = (typeof sortOptions)[number]["value"];

function keyOf(session: AgentSession): string {
  return `${session.agent}::${session.session_id}`;
}

export function AgentsClient({ initialSession }: { initialSession: string | null }) {
  const [search, setSearch] = useState("");
  const [sort, setSort] = useState<SortKey>("recent");
  const [selectedKey, setSelectedKey] = useState<string | null>(initialSession);

  const agents = useLiveData<AgentsResponse>("/v1/agents?limit=500", {
    intervalMs: 20_000,
  });

  const sessions = useMemo(() => agents.data?.sessions ?? [], [agents.data]);

  const filtered = useMemo(() => {
    const term = search.trim().toLowerCase();
    const rows = sessions.filter((session) => {
      if (!term) return true;
      return [
        session.agent,
        session.session_id,
        ...session.tools,
        ...session.sources,
      ]
        .join(" ")
        .toLowerCase()
        .includes(term);
    });
    return [...rows].sort((a, b) => {
      if (sort === "calls") return b.calls - a.calls;
      if (sort === "deny") return b.deny - a.deny;
      if (sort === "held") return b.require_approval - a.require_approval;
      return (b.last_seen ?? "").localeCompare(a.last_seen ?? "");
    });
  }, [search, sessions, sort]);

  const selected =
    sessions.find((session) => keyOf(session) === selectedKey) ??
    sessions.find((session) => session.session_id === selectedKey) ??
    filtered[0] ??
    null;

  const totals = useMemo(
    () =>
      sessions.reduce(
        (acc, session) => {
          acc.calls += session.calls;
          acc.allow += session.allow;
          acc.deny += session.deny;
          acc.hold += session.require_approval;
          acc.tools.add(session.tools.length);
          return acc;
        },
        { calls: 0, allow: 0, deny: 0, hold: 0, tools: new Set<number>() },
      ),
    [sessions],
  );

  return (
    <div className="ws-stack">
      <PageHeader
        eyebrow="Agents & sessions"
        title={
          <>
            Who acted, <em>in which session.</em>
          </>
        }
        description="Sessions are projected from audit metadata only — the gateway has no agent discovery endpoint. Each card shows real decision counts, tools and provenance for one agent/session pair."
        actions={
          <button
            type="button"
            className="ws-btn is-sm"
            onClick={() => void agents.refresh()}
            disabled={agents.isRefreshing}
          >
            <RefreshCw
              className={cn("h-3.5 w-3.5", agents.isRefreshing && "animate-spin")}
            />
            {agents.isRefreshing ? "Refreshing" : "Refresh"}
          </button>
        }
      />

      {agents.failure && agents.data ? (
        <Banner tone="warn" icon={ShieldAlert}>
          <strong>Live updates interrupted.</strong> Showing the last successful
          session snapshot. {agents.failure.message}
        </Banner>
      ) : null}

      <div className="ws-grid ws-grid-4">
        <StatCard
          label="Agent / session pairs"
          value={agents.data ? formatNumber(sessions.length) : "—"}
          meta={agents.data ? `from ${formatNumber(agents.data.sample.entries_read)} audit entries` : agents.failure ? "Gateway unreachable \u2014 retry" : "Loading\u2026"}
          icon={Users}
        />
        <StatCard
          label="Calls attributed"
          value={agents.data ? formatNumber(totals.calls) : "—"}
          meta="Only calls carrying agent or session metadata"
          icon={Activity}
        />
        <StatCard
          label="Held for approval"
          value={agents.data ? formatNumber(totals.hold) : "—"}
          meta="Human decision required"
          icon={UserCheck}
          tone="purple"
        />
        <StatCard
          label="Denied"
          value={agents.data ? formatNumber(totals.deny) : "—"}
          meta="Stopped at the boundary"
          icon={ShieldAlert}
        />
      </div>

      <div className="ws-grid ws-grid-sidebar">
        <Card>
          <CardHead
            title="Sessions"
            subtitle="Grouped by metadata.agent/agent_id + metadata.session_id/session/thread_id"
            icon={Users}
            actions={
              agents.lastUpdated ? (
                <LiveMeta
                  lastUpdated={agents.lastUpdated}
                  isRefreshing={agents.isRefreshing}
                  isStale={agents.isStale}
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
                  placeholder="Agent, session, tool or source"
                  aria-label="Search sessions"
                />
              </span>
            </label>
            <label className="ws-field">
              <span className="ws-label">Sort</span>
              <select
                className="ws-select"
                value={sort}
                onChange={(event) => setSort(event.target.value as SortKey)}
              >
                {sortOptions.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </label>
            <span className="ws-count-pill">
              {filtered.length} / {sessions.length}
            </span>
          </div>

          {agents.isLoading ? (
            <CardBody>
              <LoadingState rows={3} />
            </CardBody>
          ) : agents.failure && !agents.data ? (
            <CardBody>
              <ErrorState failure={agents.failure} onRetry={agents.refresh} />
            </CardBody>
          ) : filtered.length ? (
            <CardBody>
              <div className="ws-grid ws-grid-2">
                {filtered.map((session) => {
                  const key = keyOf(session);
                  const isSelected = selected ? keyOf(selected) === key : false;
                  return (
                    <button
                      key={key}
                      type="button"
                      className={cn("ws-session-card", isSelected && "is-selected")}
                      onClick={() => setSelectedKey(key)}
                      aria-pressed={isSelected}
                    >
                      <div className="ws-between">
                        <span className="ws-session-name">
                          <Bot className="h-4 w-4 ws-ink-soft" />
                          <span className="ws-truncate">{session.agent}</span>
                        </span>
                        {session.deny > 0 ? (
                          <StatusBadge tone="error">{session.deny} denied</StatusBadge>
                        ) : session.require_approval > 0 ? (
                          <StatusBadge tone="warn">{session.require_approval} held</StatusBadge>
                        ) : (
                          <StatusBadge tone="ok">clean</StatusBadge>
                        )}
                      </div>
                      <span className="ws-session-id">{session.session_id}</span>
                      <div className="ws-tool-stats">
                        <span className="ws-mini-stat">
                          <strong>{formatNumber(session.calls)}</strong> calls
                        </span>
                        <span className="ws-mini-stat">
                          <strong>{formatNumber(session.allow)}</strong> allow
                        </span>
                        <span className="ws-mini-stat">
                          <strong>{formatNumber(session.require_approval)}</strong> hold
                        </span>
                        <span className="ws-mini-stat">
                          <strong>{formatNumber(session.deny)}</strong> deny
                        </span>
                      </div>
                      <div className="ws-between ws-fs-meta ws-ink-faint">
                        <span>{session.tools.length} tool{session.tools.length === 1 ? "" : "s"}</span>
                        <span>{formatRelative(session.last_seen)}</span>
                      </div>
                    </button>
                  );
                })}
              </div>
            </CardBody>
          ) : sessions.length ? (
            <EmptyState
              title="No sessions match this search."
              description="Try a different agent, session ID, tool or source."
              icon={FilterX}
              action={
                <button
                  type="button"
                  className="ws-btn is-sm"
                  onClick={() => setSearch("")}
                >
                  Clear search
                </button>
              }
            />
          ) : (
            <EmptyState
              title="No agent or session metadata observed."
              description={
                <>
                  Calls without metadata are still audited but cannot be grouped.
                  Add <code className="ws-mono">metadata.agent</code> and{" "}
                  <code className="ws-mono">metadata.session_id</code> in the
                  Activity Monitor boundary check, or from your harness, to create a
                  session.
                </>
              }
              icon={Users}
            />
          )}
        </Card>

        <div className="ws-detail">
          <Card>
            <CardHead
              title="Session inspector"
              subtitle="Counts, tools and provenance from the audit trail"
              icon={Search}
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
                <div className="ws-stack">
                  <div>
                    <div className="ws-session-name">
                      <Bot className="h-4 w-4" /> {selected.agent}
                    </div>
                    <div className="ws-session-id mt-1">{selected.session_id}</div>
                  </div>
                  <Distribution
                    allow={selected.allow}
                    hold={selected.require_approval}
                    deny={selected.deny}
                  />
                  <KeyValue
                    items={[
                      { label: "Calls", value: formatNumber(selected.calls) },
                      { label: "Allowed", value: formatNumber(selected.allow) },
                      {
                        label: "Held",
                        value: formatNumber(selected.require_approval),
                      },
                      { label: "Denied", value: formatNumber(selected.deny) },
                      {
                        label: "First seen",
                        value: formatTimestamp(selected.first_seen),
                      },
                      {
                        label: "Last seen",
                        value: formatTimestamp(selected.last_seen),
                      },
                    ]}
                  />
                  <div>
                    <span className="ws-label">Tools observed</span>
                    <div className="ws-wrap mt-1.5">
                      {selected.tools.length ? (
                        selected.tools.map((tool) => (
                          <span key={tool} className="ws-badge is-neutral">
                            {tool}
                          </span>
                        ))
                      ) : (
                        <span className="ws-hint">None recorded.</span>
                      )}
                    </div>
                  </div>
                  <div>
                    <span className="ws-label">Sources observed</span>
                    <div className="ws-wrap mt-1.5">
                      {selected.sources.length ? (
                        selected.sources.map((source) => (
                          <SourceBadge key={source} source={source} />
                        ))
                      ) : (
                        <span className="ws-hint">None recorded.</span>
                      )}
                    </div>
                  </div>
                  <div className="ws-banner">
                    <Clock3 className="mt-0.5 h-4 w-4 shrink-0" />
                    <div>
                      This grouping is derived from the most recent{" "}
                      {formatNumber(agents.data?.sample.limit ?? 500)} audit entries.
                      It is not a live process registry.
                    </div>
                  </div>
                </div>
              ) : (
                <EmptyState
                  title="Select a session."
                  description="Choose a session card to inspect its decision mix, tools and provenance."
                  icon={Users}
                />
              )}
            </CardBody>
          </Card>
        </div>
      </div>

      <Banner tone="purple" icon={Users}>
        <strong>Metadata is not identity.</strong> Agent and session labels come from
        caller-supplied audit metadata. Treat them as correlation keys for
        investigation, not authenticated principal identities. Source trust is still
        resolved by the gateway provenance layer.
      </Banner>
    </div>
  );
}
