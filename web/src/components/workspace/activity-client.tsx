"use client";

import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  Bot,
  CheckCircle2,
  FilterX,
  FlaskConical,
  RefreshCw,
  Search,
  Send,
  ShieldAlert,
  Terminal,
} from "lucide-react";
import Link from "next/link";
import { useMemo, useState, type FormEvent } from "react";
import { apiPost } from "@/lib/api/client";
import { toApiFailure, type ApiFailure } from "@/lib/api/errors";
import {
  formatNumber,
  formatRelative,
  formatTimestamp,
  sourceLabel,
} from "@/lib/api/format";
import type {
  AuditEntry,
  AuditResponse,
  CheckResponse,
  EnforceResponse,
  HealthResponse,
} from "@/lib/api/types";
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
  InlineLoading,
  KeyValue,
  LiveMeta,
  LoadingState,
  PageHeader,
  ProvenanceIndicator,
  ReasonList,
  SourceBadge,
  StatCard,
  StatusBadge,
} from "@/components/workspace/ui";

const limits = [50, 100, 250, 500] as const;
const decisions = ["all", "allow", "require_approval", "deny"] as const;
const sources = ["all", "user", "system", "trusted_tool", "untrusted"] as const;

const sampleArguments = '{\n  "query": "approved Q3 vendors"\n}';

function metadataFor(agent: string, session: string): Record<string, unknown> {
  const metadata: Record<string, unknown> = {};
  if (agent.trim()) metadata.agent = agent.trim();
  if (session.trim()) metadata.session_id = session.trim();
  return metadata;
}

export function ActivityClient() {
  const [limit, setLimit] = useState<number>(100);
  const [decision, setDecision] = useState<(typeof decisions)[number]>("all");
  const [source, setSource] = useState<(typeof sources)[number]>("all");
  const [search, setSearch] = useState("");
  const [selectedCall, setSelectedCall] = useState<string | null>(null);

  const [toolName, setToolName] = useState("search_web");
  const [argumentsText, setArgumentsText] = useState(sampleArguments);
  const [checkSource, setCheckSource] = useState("user");
  const [context, setContext] = useState("");
  const [agent, setAgent] = useState("");
  const [session, setSession] = useState("");
  const [formError, setFormError] = useState<string | null>(null);
  const [submitFailure, setSubmitFailure] = useState<ApiFailure | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<CheckResponse | null>(null);

  const audit = useLiveData<AuditResponse>(`/v1/audit?limit=${limit}`, {
    intervalMs: 10_000,
  });
  const enforce = useLiveData<EnforceResponse>("/v1/enforce", {
    intervalMs: 15_000,
  });
  const health = useLiveData<HealthResponse>("/health", { intervalMs: 20_000 });

  const entries = useMemo(() => audit.data?.entries ?? [], [audit.data]);
  const filtered = useMemo(() => {
    const term = search.trim().toLowerCase();
    return entries.filter((entry) => {
      if (decision !== "all" && entry.decision !== decision) return false;
      if (source !== "all" && entry.source !== source) return false;
      if (!term) return true;
      const metadata = entry.metadata ?? {};
      return [
        entry.call_id,
        entry.tool,
        entry.source,
        entry.decision,
        String(metadata.agent ?? metadata.agent_id ?? ""),
        String(
          metadata.session_id ?? metadata.session ?? metadata.thread_id ?? "",
        ),
      ]
        .join(" ")
        .toLowerCase()
        .includes(term);
    });
  }, [decision, entries, search, source]);

  const selected =
    entries.find((entry) => entry.call_id === selectedCall) ??
    filtered[0] ??
    null;

  const activeFilters =
    decision !== "all" || source !== "all" || search.trim().length > 0;

  const refreshAll = () => {
    void Promise.all([audit.refresh(), enforce.refresh(), health.refresh()]);
  };

  const clearFilters = () => {
    setDecision("all");
    setSource("all");
    setSearch("");
  };

  const submitCheck = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setFormError(null);
    setSubmitFailure(null);

    const trimmedTool = toolName.trim();
    if (!trimmedTool) {
      setFormError("A tool name is required.");
      return;
    }

    let parsedArguments: Record<string, unknown>;
    try {
      const parsed: unknown = JSON.parse(argumentsText || "{}");
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        setFormError("Arguments must be a JSON object, for example {\"query\":\"…\"}.");
        return;
      }
      parsedArguments = parsed as Record<string, unknown>;
    } catch {
      setFormError("Arguments are not valid JSON. Fix the payload before sending.");
      return;
    }

    setSubmitting(true);
    try {
      const response = await apiPost<CheckResponse>("/v1/check", {
        tool_name: trimmedTool,
        arguments: parsedArguments,
        source: checkSource,
        context,
        metadata: metadataFor(agent, session),
      });
      setResult(response);
      setSelectedCall(response.call_id);
      await Promise.all([audit.refresh(), enforce.refresh()]);
    } catch (error) {
      setSubmitFailure(toApiFailure(error));
    } finally {
      setSubmitting(false);
    }
  };

  const gatewayDown = health.failure && !health.data;

  return (
    <div className="ws-stack">
      <PageHeader
        eyebrow="Activity monitor"
        title={
          <>
            Every call, <em>decided.</em>
          </>
        }
        description="The audit trail is append-only. Inspect real tool-call decisions, filter by verdict or provenance, and send a proposed call through the policy decision point to see the exact reasons the gateway returns."
        actions={
          <button
            type="button"
            className="ws-btn is-sm"
            onClick={refreshAll}
            disabled={audit.isRefreshing}
          >
            <RefreshCw
              className={cn("h-3.5 w-3.5", audit.isRefreshing && "animate-spin")}
            />
            {audit.isRefreshing ? "Refreshing" : "Refresh"}
          </button>
        }
      />

      {gatewayDown ? (
        <ErrorState failure={health.failure!} onRetry={refreshAll} />
      ) : null}
      {audit.failure && audit.data ? (
        <Banner tone="warn" icon={AlertTriangle}>
          <strong>Live updates interrupted.</strong> Showing the last successful
          audit snapshot. {audit.failure.message}
        </Banner>
      ) : null}
      {enforce.data && !enforce.data.enforced ? (
        <Banner tone="warn" icon={ShieldAlert}>
          <strong>Global enforcement is OFF.</strong> The gateway still evaluates,
          detects and audits every call, but returns ALLOW with an{" "}
          <code className="ws-mono">enforcement_disabled</code> reason that names the
          would-be verdict. Boundary checks below reflect that live switch.
        </Banner>
      ) : null}

      <div className="ws-grid ws-grid-4">
        <StatCard
          label="Entries in sample"
          value={audit.data ? formatNumber(entries.length) : "—"}
          meta={audit.data ? `limit ${limit} · newest first` : audit.failure ? "Gateway unreachable \u2014 retry" : "Loading\u2026"}
          icon={Activity}
        />
        <StatCard
          label="Allowed"
          value={
            audit.data
              ? formatNumber(entries.filter((entry) => entry.decision === "allow").length)
              : "—"
          }
          meta="Explicit policy allow"
          icon={CheckCircle2}
          tone="lime"
        />
        <StatCard
          label="Held"
          value={
            audit.data
              ? formatNumber(
                  entries.filter((entry) => entry.decision === "require_approval")
                    .length,
                )
              : "—"
          }
          meta="Single-use human decision required"
          icon={Bot}
          tone="purple"
        />
        <StatCard
          label="Denied"
          value={
            audit.data
              ? formatNumber(entries.filter((entry) => entry.decision === "deny").length)
              : "—"
          }
          meta="Never reached the tool"
          icon={ShieldAlert}
        />
      </div>

      <div className="ws-grid ws-grid-sidebar">
        <Card>
          <CardHead
            title="Decision trail"
            subtitle="Read directly from GET /v1/audit · bounded to the selected limit"
            icon={Terminal}
            actions={
              audit.lastUpdated ? (
                <LiveMeta
                  lastUpdated={audit.lastUpdated}
                  isRefreshing={audit.isRefreshing}
                  isStale={audit.isStale}
                  intervalLabel="10s"
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
                  placeholder="Tool, call ID, agent, session"
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
              <span className="ws-label">Source</span>
              <select
                className="ws-select"
                value={source}
                onChange={(event) =>
                  setSource(event.target.value as (typeof sources)[number])
                }
              >
                {sources.map((value) => (
                  <option key={value} value={value}>
                    {value === "all" ? "All sources" : sourceLabel(value)}
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
              <button type="button" className="ws-btn is-xs is-ghost" onClick={clearFilters}>
                <FilterX className="h-3 w-3" /> Clear
              </button>
            ) : null}
          </div>

          {audit.isLoading ? (
            <CardBody>
              <LoadingState rows={3} />
            </CardBody>
          ) : audit.failure && !audit.data ? (
            <CardBody>
              <ErrorState failure={audit.failure} onRetry={audit.refresh} />
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
                    <th>Call ID</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((entry) => {
                    const metadata = entry.metadata ?? {};
                    const agentName =
                      String(metadata.agent ?? metadata.agent_id ?? "") || "—";
                    const sessionId =
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
                        aria-label={`Inspect ${entry.tool} decision ${entry.decision}`}
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
                          {agentName}
                          {sessionId ? (
                            <span className="block font-mono ws-fs-meta ws-ink-faint">
                              {sessionId}
                            </span>
                          ) : null}
                        </td>
                        <td>
                          <button
                            type="button"
                            className="ws-link font-mono ws-fs-meta"
                            onClick={(event) => {
                              event.stopPropagation();
                              setSelectedCall(entry.call_id);
                            }}
                          >
                            {entry.call_id}
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          ) : entries.length ? (
            <EmptyState
              title="No records match these filters."
              description="Clear the filters or widen the audit sample."
              icon={FilterX}
              action={
                <button type="button" className="ws-btn is-sm" onClick={clearFilters}>
                  Clear filters
                </button>
              }
            />
          ) : (
            <EmptyState
              title="No audit entries yet."
              description="Send a boundary check below. The gateway will evaluate it, write a decision record and return the exact policy reasons."
              icon={Terminal}
            />
          )}
        </Card>

        <div className="ws-detail">
          <Card>
            <CardHead
              title="Record inspector"
              subtitle="Full audit fields, policy reasons and detector output"
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
              {selected ? <AuditDetail entry={selected} /> : (
                <EmptyState
                  title="Select a decision record."
                  description="Choose a row in the trail to inspect its arguments, policy reasons, detector output and provenance."
                  icon={Activity}
                />
              )}
            </CardBody>
          </Card>
        </div>
      </div>

      <div className="ws-grid ws-grid-main">
        <Card>
          <CardHead
            title="Boundary check"
            subtitle="POST /v1/check · returns an advisory verdict and writes an audit record"
            icon={Send}
            actions={<StatusBadge tone="purple">PDP</StatusBadge>}
          />
          <CardBody>
            <form className="ws-stack" onSubmit={submitCheck}>
              <div className="ws-grid ws-grid-2">
                <label className="ws-field">
                  <span className="ws-label">Tool name</span>
                  <input
                    className="ws-input"
                    value={toolName}
                    onChange={(event) => setToolName(event.target.value)}
                    placeholder="send_email"
                    autoComplete="off"
                    required
                  />
                </label>
                <label className="ws-field">
                  <span className="ws-label">Asserted source</span>
                  <select
                    className="ws-select"
                    value={checkSource}
                    onChange={(event) => setCheckSource(event.target.value)}
                  >
                    {sources
                      .filter((value) => value !== "all")
                      .map((value) => (
                        <option key={value} value={value}>
                          {sourceLabel(value)}
                        </option>
                      ))}
                  </select>
                </label>
              </div>

              <label className="ws-field">
                <span className="ws-label">Arguments · JSON object</span>
                <textarea
                  className="ws-textarea"
                  value={argumentsText}
                  onChange={(event) => setArgumentsText(event.target.value)}
                  spellCheck={false}
                  aria-describedby="arguments-hint"
                />
                <span className="ws-hint" id="arguments-hint">
                  The exact arguments are hashed into any approval decision. Invalid
                  JSON is rejected before the request is sent.
                </span>
              </label>

              <label className="ws-field">
                <span className="ws-label">Context · optional</span>
                <textarea
                  className="ws-textarea is-short"
                  value={context}
                  onChange={(event) => setContext(event.target.value)}
                  placeholder="The untrusted document or email text the agent was processing."
                />
              </label>

              <div className="ws-grid ws-grid-2">
                <label className="ws-field">
                  <span className="ws-label">Agent metadata · optional</span>
                  <input
                    className="ws-input"
                    value={agent}
                    onChange={(event) => setAgent(event.target.value)}
                    placeholder="research-agent"
                    autoComplete="off"
                  />
                </label>
                <label className="ws-field">
                  <span className="ws-label">Session metadata · optional</span>
                  <input
                    className="ws-input"
                    value={session}
                    onChange={(event) => setSession(event.target.value)}
                    placeholder="sess_01"
                    autoComplete="off"
                  />
                </label>
              </div>

              {formError ? (
                <Banner tone="error" icon={AlertTriangle}>
                  {formError}
                </Banner>
              ) : null}
              {submitFailure ? <ErrorState failure={submitFailure} compact /> : null}

              <div className="ws-between">
                <p className="ws-hint">
                  Source is only a claim. Without a valid provenance token the
                  gateway resolves it to UNTRUSTED; the response shows the resolved
                  source.
                </p>
                <div className="ws-row shrink-0">
                  <button
                    type="button"
                    className="ws-btn is-sm is-ghost"
                    onClick={() => {
                      setArgumentsText(sampleArguments);
                      setContext("");
                      setAgent("");
                      setSession("");
                      setFormError(null);
                      setSubmitFailure(null);
                    }}
                    disabled={submitting}
                  >
                    Reset
                  </button>
                  <button
                    type="submit"
                    className="ws-btn is-primary is-sm"
                    disabled={submitting || !toolName.trim()}
                  >
                    {submitting ? (
                      <InlineLoading label="Evaluating" />
                    ) : (
                      <>
                        <Send className="h-3.5 w-3.5" /> Send check
                      </>
                    )}
                  </button>
                </div>
              </div>
            </form>
          </CardBody>
        </Card>

        <Card>
          <CardHead
            title="Last boundary result"
            subtitle="Returned by this browser session · not a stored approval"
            icon={CheckCircle2}
            actions={
              result ? <DecisionBadge decision={result.decision} /> : null
            }
          />
          <CardBody>
            {result ? (
              <div className="ws-stack">
                <div className={cn("ws-verdict", `is-${result.decision === "require_approval" ? "hold" : result.decision}`)}>
                  <div className="ws-verdict-label">Gateway verdict</div>
                  <div className="ws-verdict-value">{result.headline}</div>
                  <p className="ws-verdict-detail">
                    {result.fail_closed
                      ? "Fail-closed: the gateway escalated because a detector or policy input could not be trusted."
                      : "The decision is advisory at this endpoint. Enforcement happens at the execution path."}
                  </p>
                </div>
                <KeyValue
                  items={[
                    {
                      label: "Call ID",
                      value: (
                        <span className="flex items-center gap-2">
                          <span className="font-mono ws-fs-meta">{result.call_id}</span>
                          <CopyButton value={result.call_id} label="Copy" />
                        </span>
                      ),
                    },
                    {
                      label: "Resolved source",
                      value: <SourceBadge source={result.resolved_source} />,
                    },
                    {
                      label: "Fail closed",
                      value: result.fail_closed ? (
                        <StatusBadge tone="warn">yes</StatusBadge>
                      ) : (
                        <StatusBadge tone="ok">no</StatusBadge>
                      ),
                    },
                    {
                      label: "Enforcement",
                      value: enforce.data ? (
                        <StatusBadge tone={enforce.data.enforced ? "ok" : "warn"}>
                          {enforce.data.enforced ? "ON" : "OFF"}
                        </StatusBadge>
                      ) : (
                        "Unknown"
                      ),
                    },
                  ]}
                />
                <ReasonList reasons={result.reasons} />
                <Link
                  href={`/workspace/audit?call=${encodeURIComponent(result.call_id)}`}
                  className="ws-link"
                >
                  Open in Audit &amp; Forensics <ArrowUpRight className="h-3 w-3" />
                </Link>
              </div>
            ) : (
              <EmptyState
                title="No check sent in this session."
                description="Submit a proposed tool call to see the real verdict, resolved provenance and ordered policy reasons. The call is audited even though no tool executes."
                icon={Send}
              />
            )}
          </CardBody>
        </Card>
      </div>

      <Banner tone="purple" icon={FlaskConical}>
        <strong>What this page does not claim.</strong> The activity table reads the
        last {limit} audit entries only; the gateway may hold more. No latency or
        cost is shown because the audit schema does not record processing duration.
        Use the Red Team Lab for an isolated ON/OFF comparison.
      </Banner>
    </div>
  );
}

function AuditDetail({ entry }: { entry: AuditEntry }) {
  const metadata = entry.metadata ?? {};
  const agent = String(metadata.agent ?? metadata.agent_id ?? "") || "—";
  const session =
    String(metadata.session_id ?? metadata.session ?? metadata.thread_id ?? "") ||
    "—";

  return (
    <div className="ws-stack">
      <div className="ws-between">
        <DecisionBadge decision={entry.decision} />
        <SourceBadge source={entry.source} />
      </div>
      <ProvenanceIndicator source={entry.source} />
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
            value: entry.fail_closed ? "yes" : "no",
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
        ]}
      />
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
    </div>
  );
}
