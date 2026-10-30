"use client";

import {
  AlertTriangle,
  ArrowUpRight,
  FilterX,
  FlaskConical,
  RefreshCw,
  Search,
  ShieldAlert,
  Sparkles,
  Target,
} from "lucide-react";
import Link from "next/link";
import { useMemo, useState } from "react";
import {
  formatNumber,
  formatTimestamp,
} from "@/lib/api/format";
import type { ThreatEvent, ThreatsResponse } from "@/lib/api/types";
import { useLiveData } from "@/lib/hooks/use-live-data";
import { cn } from "@/lib/utils";
import { CopyButton } from "@/components/workspace/copy-button";
import { JsonBlock } from "@/components/workspace/json-block";
import {
  Banner,
  Bars,
  Card,
  CardBody,
  CardHead,
  DecisionBadge,
  EmptyState,
  ErrorState,
  InferredBadge,
  KeyValue,
  LiveMeta,
  LoadingState,
  PageHeader,
  ReasonList,
  SeverityBadge,
  SourceBadge,
  StatCard,
  StatusBadge,
} from "@/components/workspace/ui";

const severities = ["all", "high", "medium", "low"] as const;
const decisions = ["all", "allow", "require_approval", "deny"] as const;

export function ThreatsClient({ initialEvent }: { initialEvent: string | null }) {
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState<(typeof severities)[number]>("all");
  const [decision, setDecision] = useState<(typeof decisions)[number]>("all");
  const [category, setCategory] = useState("all");
  const [detector, setDetector] = useState("all");
  const [selectedId, setSelectedId] = useState<string | null>(initialEvent);

  const threats = useLiveData<ThreatsResponse>("/v1/threats?limit=500", {
    intervalMs: 20_000,
  });

  const events = useMemo(() => threats.data?.events ?? [], [threats.data]);
  const categories = threats.data?.categories ?? [];
  const detectors = useMemo(
    () => Array.from(new Set(events.map((event) => event.detector))).sort(),
    [events],
  );

  const filtered = useMemo(() => {
    const term = search.trim().toLowerCase();
    return events.filter((event) => {
      if (severity !== "all" && event.severity !== severity) return false;
      if (decision !== "all" && event.decision !== decision) return false;
      if (category !== "all" && event.category !== category) return false;
      if (detector !== "all" && event.detector !== detector) return false;
      if (!term) return true;
      return [
        event.threat_id,
        event.call_id,
        event.tool,
        event.detector,
        event.category,
        event.category_label,
        event.source,
        ...event.signals,
      ]
        .join(" ")
        .toLowerCase()
        .includes(term);
    });
  }, [category, decision, detector, events, search, severity]);

  const selected =
    events.find((event) => event.threat_id === selectedId) ??
    filtered[0] ??
    null;

  const activeFilters =
    search.trim().length > 0 ||
    severity !== "all" ||
    decision !== "all" ||
    category !== "all" ||
    detector !== "all";

  const clearFilters = () => {
    setSearch("");
    setSeverity("all");
    setDecision("all");
    setCategory("all");
    setDetector("all");
  };

  return (
    <div className="ws-stack">
      <PageHeader
        eyebrow="Threat intelligence"
        title={
          <>
            Signals, <em>not guesses.</em>
          </>
        }
        description="Every event below comes from a real detector finding in the audit trail. Category and severity are inferred presentation labels derived from detector signals, scores and the final policy decision — they are not separate detector verdicts."
        actions={
          <button
            type="button"
            className="ws-btn is-sm"
            onClick={() => void threats.refresh()}
            disabled={threats.isRefreshing}
          >
            <RefreshCw
              className={cn("h-3.5 w-3.5", threats.isRefreshing && "animate-spin")}
            />
            {threats.isRefreshing ? "Refreshing" : "Refresh"}
          </button>
        }
      />

      {threats.failure && threats.data ? (
        <Banner tone="warn" icon={AlertTriangle}>
          <strong>Live updates interrupted.</strong> Showing the last successful threat
          snapshot. {threats.failure.message}
        </Banner>
      ) : null}

      <div className="ws-grid ws-grid-4">
        <StatCard
          label="Detector findings"
          value={threats.data ? formatNumber(threats.data.total) : "—"}
          meta={threats.data ? `from ${formatNumber(threats.data.sample.entries_read)} audit entries` : "Waiting for gateway"}
          icon={ShieldAlert}
        />
        <StatCard
          label="High severity"
          value={threats.data ? formatNumber(threats.data.severity.high) : "—"}
          meta="Deny or score ≥ 0.85"
          icon={Target}
        />
        <StatCard
          label="Medium severity"
          value={threats.data ? formatNumber(threats.data.severity.medium) : "—"}
          meta="Approval or score ≥ 0.60"
          icon={AlertTriangle}
          tone="purple"
        />
        <StatCard
          label="Low severity"
          value={threats.data ? formatNumber(threats.data.severity.low) : "—"}
          meta="Remaining detector signals"
          icon={Sparkles}
          tone="lime"
        />
      </div>

      <div className="ws-grid ws-grid-2">
        <Card>
          <CardHead
            title="Inferred categories"
            subtitle="Presentation grouping only · never a detector verdict"
            icon={Sparkles}
            actions={<InferredBadge />}
          />
          <CardBody>
            {threats.data ? (
              <Bars
                rows={categories.map((row) => ({
                  label: row.label,
                  value: row.count,
                  note: `${row.count}`,
                  tone: row.key === "payment_fraud" || row.key === "data_exfiltration" ? "red" : "purple",
                }))}
                empty="No detector-flagged events in the retained sample."
              />
            ) : threats.failure ? (
              <ErrorState failure={threats.failure} onRetry={threats.refresh} compact />
            ) : (
              <LoadingState rows={2} />
            )}
          </CardBody>
        </Card>

        <Card>
          <CardHead
            title="Classification basis"
            subtitle="How the console labels what the detector already found"
            icon={ShieldAlert}
          />
          <CardBody>
            <div className="ws-stack">
              <p className="ws-small">
                {threats.data?.classification_note ??
                  "Categories and severity are inferred presentation labels derived from real detector signals, scores and the final policy decision."}
              </p>
              <KeyValue
                items={[
                  {
                    label: "Severity high",
                    value: "final decision is deny, or detector score ≥ 0.85",
                  },
                  {
                    label: "Severity medium",
                    value: "final decision is require_approval, or score ≥ 0.60",
                  },
                  {
                    label: "Severity low",
                    value: "all other real detector findings",
                  },
                  {
                    label: "Context",
                    value: "Raw document context is not persisted in the audit trail.",
                  },
                ]}
              />
              <div className="ws-rule-note">
                <Sparkles className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                <span>
                  Category names are a UI affordance for triage. The authoritative
                  evidence is the detector name, score, signals and policy reasons on
                  each record.
                </span>
              </div>
            </div>
          </CardBody>
        </Card>
      </div>

      <div className="ws-grid ws-grid-sidebar">
        <Card>
          <CardHead
            title="Threat events"
            subtitle="Newest first · real detector findings only"
            icon={ShieldAlert}
            actions={
              threats.lastUpdated ? (
                <LiveMeta
                  lastUpdated={threats.lastUpdated}
                  isRefreshing={threats.isRefreshing}
                  isStale={threats.isStale}
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
                  placeholder="Tool, signal, call or category"
                  aria-label="Search threat events"
                />
              </span>
            </label>
            <label className="ws-field">
              <span className="ws-label">Severity</span>
              <select
                className="ws-select"
                value={severity}
                onChange={(event) =>
                  setSeverity(event.target.value as (typeof severities)[number])
                }
              >
                {severities.map((value) => (
                  <option key={value} value={value}>
                    {value === "all" ? "All severities" : value}
                  </option>
                ))}
              </select>
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
              <span className="ws-label">Category</span>
              <select
                className="ws-select"
                value={category}
                onChange={(event) => setCategory(event.target.value)}
              >
                <option value="all">All categories</option>
                {categories.map((row) => (
                  <option key={row.key} value={row.key}>
                    {row.label}
                  </option>
                ))}
              </select>
            </label>
            <label className="ws-field">
              <span className="ws-label">Detector</span>
              <select
                className="ws-select"
                value={detector}
                onChange={(event) => setDetector(event.target.value)}
              >
                <option value="all">All detectors</option>
                {detectors.map((value) => (
                  <option key={value} value={value}>
                    {value}
                  </option>
                ))}
              </select>
            </label>
            <span className="ws-count-pill">
              {filtered.length} / {events.length}
            </span>
            {activeFilters ? (
              <button type="button" className="ws-btn is-xs is-ghost" onClick={clearFilters}>
                <FilterX className="h-3 w-3" /> Clear
              </button>
            ) : null}
          </div>

          {threats.isLoading ? (
            <CardBody>
              <LoadingState rows={3} />
            </CardBody>
          ) : threats.failure && !threats.data ? (
            <CardBody>
              <ErrorState failure={threats.failure} onRetry={threats.refresh} />
            </CardBody>
          ) : filtered.length ? (
            <div className="ws-table-wrap">
              <table className="ws-table">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Severity</th>
                    <th>Category</th>
                    <th>Detector</th>
                    <th>Tool</th>
                    <th>Decision</th>
                    <th>Score</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((event) => (
                    <tr
                      key={event.threat_id}
                      className={cn(
                        "is-clickable",
                        selected?.threat_id === event.threat_id && "is-selected",
                      )}
                      onClick={() => setSelectedId(event.threat_id)}
                      tabIndex={0}
                      onKeyDown={(keyEvent) => {
                        if (keyEvent.key === "Enter" || keyEvent.key === " ") {
                          keyEvent.preventDefault();
                          setSelectedId(event.threat_id);
                        }
                      }}
                      aria-label={`Inspect ${event.category_label} finding on ${event.tool}`}
                    >
                      <td className="is-nowrap text-[10.5px] text-[#6f6c66]">
                        {formatTimestamp(event.timestamp ?? event.epoch)}
                      </td>
                      <td>
                        <SeverityBadge severity={event.severity} />
                      </td>
                      <td className="text-[10.5px]">{event.category_label}</td>
                      <td className="font-mono text-[10px]">{event.detector}</td>
                      <td className="font-mono text-[10px]">{event.tool}</td>
                      <td>
                        <DecisionBadge decision={event.decision} short />
                      </td>
                      <td className="is-nowrap font-mono text-[10px]">
                        {event.score.toFixed(2)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : events.length ? (
            <EmptyState
              title="No findings match these filters."
              description="Clear the filters or widen the retained audit sample."
              icon={FilterX}
              action={
                <button type="button" className="ws-btn is-sm" onClick={clearFilters}>
                  Clear filters
                </button>
              }
            />
          ) : (
            <EmptyState
              title="No detector findings in the retained sample."
              description="That is not a claim that no attack exists. It means the most recent audit entries contain no threat signal. Run a known attack in the Red Team Lab to exercise the detector."
              icon={ShieldAlert}
              action={
                <Link href="/workspace/redteam" className="ws-btn is-sm">
                  <FlaskConical className="h-3.5 w-3.5" /> Open Red Team Lab
                </Link>
              }
            />
          )}
        </Card>

        <div className="ws-detail">
          <Card>
            <CardHead
              title="Finding inspector"
              subtitle="Signals, policy reasons and the originating audit record"
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
                <ThreatDetail event={selected} />
              ) : (
                <EmptyState
                  title="Select a finding."
                  description="Choose an event to inspect its detector signals, inferred label basis, policy reasons and full audit record."
                  icon={Target}
                />
              )}
            </CardBody>
          </Card>
        </div>
      </div>

      <Banner tone="purple" icon={Sparkles}>
        <strong>No fabricated intelligence.</strong> This page does not aggregate
        external threat feeds or assign MITRE techniques. It shows only detector
        findings present in the gateway audit sample.{" "}
        {threats.data?.sample.truncated
          ? "The sample limit was reached; older retained findings are outside this view."
          : ""}
      </Banner>
    </div>
  );
}

function ThreatDetail({ event }: { event: ThreatEvent }) {
  return (
    <div className="ws-stack">
      <div className="ws-between">
        <div className="ws-wrap">
          <SeverityBadge severity={event.severity} />
          <InferredBadge />
        </div>
        <DecisionBadge decision={event.decision} />
      </div>
      <div>
        <div className="text-[15px] font-semibold tracking-[-0.03em]">
          {event.category_label}
        </div>
        <p className="ws-hint mt-1">
          {event.severity_basis}. Category inferred from detector signals, score and
          final policy decision.
        </p>
      </div>
      <KeyValue
        items={[
          { label: "Threat ID", value: event.threat_id, mono: true },
          { label: "Call ID", value: event.call_id, mono: true },
          { label: "Time", value: formatTimestamp(event.timestamp ?? event.epoch) },
          { label: "Tool", value: event.tool, mono: true },
          { label: "Source", value: <SourceBadge source={event.source} /> },
          { label: "Detector", value: event.detector, mono: true },
          { label: "Score", value: event.score.toFixed(3), mono: true },
          {
            label: "Fail closed",
            value: event.fail_closed ? (
              <StatusBadge tone="warn">yes</StatusBadge>
            ) : (
              <StatusBadge tone="ok">no</StatusBadge>
            ),
          },
          {
            label: "Severity label",
            value: `${event.severity_label} · inferred`,
          },
        ]}
      />
      <div>
        <span className="ws-label">Detector signals</span>
        <div className="ws-signal-list">
          {event.signals.length ? (
            event.signals.map((signal) => (
              <span className="ws-signal" key={signal}>
                {signal}
              </span>
            ))
          ) : (
            <span className="ws-hint">No individual signals returned.</span>
          )}
        </div>
      </div>
      <div>
        <span className="ws-label">Policy reasons</span>
        <ReasonList reasons={event.reasons ?? []} />
      </div>
      <div className="ws-banner is-warn">
        <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
        <div>
          {event.context_note} Raw context is unavailable; use the Red Team Lab to see
          the exact payload that was executed.
        </div>
      </div>
      <JsonBlock value={event.arguments} title="Arguments" collapsedLines={10} />
      <JsonBlock value={event.audit_entry} title="Originating audit record" collapsedLines={14} />
      <Link
        href={`/workspace/audit?call=${encodeURIComponent(event.call_id)}`}
        className="ws-link"
      >
        Open in Audit &amp; Forensics <ArrowUpRight className="h-3 w-3" />
      </Link>
    </div>
  );
}
