"use client";

import {
  AlertTriangle,
  ArrowUpRight,
  Check,
  Clock3,
  FilterX,
  KeyRound,
  RefreshCw,
  Search,
  ShieldCheck,
  UserCheck,
  X,
} from "lucide-react";
import Link from "next/link";
import { useMemo, useState } from "react";
import { apiPost, callPath } from "@/lib/api/client";
import { toApiFailure, type ApiFailure } from "@/lib/api/errors";
import {
  formatNumber,
  formatRelative,
  formatTimestamp,
} from "@/lib/api/format";
import type {
  ApprovalDecisionResponse,
  ApprovalsResponse,
} from "@/lib/api/types";
import { useLiveData } from "@/lib/hooks/use-live-data";
import { cn } from "@/lib/utils";
import { ConfirmDialog } from "@/components/workspace/confirm-dialog";
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
  LiveMeta,
  LoadingState,
  PageHeader,
  ReasonList,
  SourceBadge,
  StatCard,
  StatusBadge,
  SuccessNote,
} from "@/components/workspace/ui";

type Verdict = "approve" | "deny";

export function ApprovalsClient() {
  const [search, setSearch] = useState("");
  const [selectedCall, setSelectedCall] = useState<string | null>(null);
  const [approver, setApprover] = useState("console-human");
  const [pendingVerdict, setPendingVerdict] = useState<Verdict | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [failure, setFailure] = useState<ApiFailure | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const approvals = useLiveData<ApprovalsResponse>("/v1/approvals?limit=500", {
    intervalMs: 15_000,
  });

  const pending = useMemo(() => approvals.data?.pending ?? [], [approvals.data]);
  const recent = useMemo(() => approvals.data?.recent ?? [], [approvals.data]);
  const summary = approvals.data?.summary;

  const filteredPending = useMemo(() => {
    const term = search.trim().toLowerCase();
    if (!term) return pending;
    return pending.filter((entry) =>
      [entry.call_id, entry.tool, entry.source, entry.reasons?.[0]?.detail ?? ""]
        .join(" ")
        .toLowerCase()
        .includes(term),
    );
  }, [pending, search]);

  const selected =
    pending.find((entry) => entry.call_id === selectedCall) ??
    recent.find((entry) => entry.call_id === selectedCall) ??
    filteredPending[0] ??
    null;

  const isPending = selected ? pending.some((entry) => entry.call_id === selected.call_id) : false;

  const refresh = () => void approvals.refresh();

  const decide = async () => {
    if (!selected || !pendingVerdict) return;
    if (!approver.trim()) {
      setFailure({
        kind: "unknown",
        status: null,
        message: "An approver label is required.",
      });
      return;
    }
    setSubmitting(true);
    setFailure(null);
    setSuccess(null);
    try {
      const result = await apiPost<ApprovalDecisionResponse>(
        callPath(selected.call_id),
        { verdict: pendingVerdict, approver: approver.trim() },
      );
      setSuccess(
        pendingVerdict === "approve"
          ? `Approved ${selected.call_id}. The approval is single-use and bound to the exact argument hash. It does not grant standing access.`
          : `Denied ${selected.call_id}. The call will not execute; the decision is recorded in the append-only trail.`,
      );
      setPendingVerdict(null);
      setSelectedCall(result.entry.call_id);
      await approvals.refresh();
    } catch (error) {
      setFailure(toApiFailure(error));
      setPendingVerdict(null);
      await approvals.refresh();
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="ws-stack">
      <PageHeader
        eyebrow="Approval center"
        title={
          <>
            Human judgment, <em>once.</em>
          </>
        }
        description="Calls held by policy wait here for a named human decision. The gateway enforces single-use, argument-hash-bound approvals. This page never changes approval state locally — it sends the decision and re-reads the queue."
        actions={
          <button
            type="button"
            className="ws-btn is-sm"
            onClick={refresh}
            disabled={approvals.isRefreshing}
          >
            <RefreshCw
              className={cn("h-3.5 w-3.5", approvals.isRefreshing && "animate-spin")}
            />
            {approvals.isRefreshing ? "Refreshing" : "Refresh"}
          </button>
        }
      />

      {approvals.failure && approvals.data ? (
        <Banner tone="warn" icon={AlertTriangle}>
          <strong>Live updates interrupted.</strong> Showing the last successful
          approval snapshot. {approvals.failure.message}
        </Banner>
      ) : null}
      {failure ? <ErrorState failure={failure} compact onRetry={refresh} /> : null}
      {success ? <SuccessNote>{success}</SuccessNote> : null}

      <div className="ws-grid ws-grid-4">
        <StatCard
          label="Pending decisions"
          value={approvals.data ? formatNumber(summary?.pending ?? pending.length) : "—"}
          meta="Held by the current policy"
          icon={UserCheck}
          tone={(summary?.pending ?? 0) > 0 ? "purple" : undefined}
        />
        <StatCard
          label="Approved"
          value={approvals.data ? formatNumber(summary?.approved ?? 0) : "—"}
          meta="In the retained audit sample"
          icon={Check}
          tone="lime"
        />
        <StatCard
          label="Rejected"
          value={approvals.data ? formatNumber(summary?.rejected ?? 0) : "—"}
          meta="Denied by a human"
          icon={X}
        />
        <StatCard
          label="Consumed"
          value={approvals.data ? formatNumber(summary?.consumed ?? 0) : "—"}
          meta="Single-use approvals already used"
          icon={ShieldCheck}
        />
      </div>

      <Card>
        <CardHead
          title="Approval guarantees"
          subtitle="Read from GET /v1/approvals · capabilities reported by the gateway"
          icon={KeyRound}
          actions={
            approvals.lastUpdated ? (
              <LiveMeta
                lastUpdated={approvals.lastUpdated}
                isRefreshing={approvals.isRefreshing}
                isStale={approvals.isStale}
                intervalLabel="15s"
              />
            ) : null
          }
        />
        <CardBody>
          <div className="ws-grid ws-grid-4">
            <div className="ws-verdict">
              <div className="ws-verdict-label">Single use</div>
              <div className="ws-verdict-value text-[19px]">
                {approvals.data?.capabilities.single_use ? "Enforced" : "Unknown"}
              </div>
              <p className="ws-verdict-detail">
                A live decision cannot be replayed for another call.
              </p>
            </div>
            <div className="ws-verdict">
              <div className="ws-verdict-label">Argument bound</div>
              <div className="ws-verdict-value text-[19px]">
                {approvals.data?.capabilities.args_hash_bound ? "Enforced" : "Unknown"}
              </div>
              <p className="ws-verdict-detail">
                The decision is bound to the exact argument hash.
              </p>
            </div>
            <div className="ws-verdict">
              <div className="ws-verdict-label">Expiry</div>
              <div className="ws-verdict-value text-[19px]">
                {approvals.data?.capabilities.expiry ? "Enforced" : "Not implemented"}
              </div>
              <p className="ws-verdict-detail">
                {approvals.data?.notes.expiry ??
                  "Approval expiry is not implemented in the backend."}
              </p>
            </div>
            <div className="ws-verdict">
              <div className="ws-verdict-label">Decision endpoint</div>
              <div className="ws-verdict-value text-[19px]">
                {approvals.data?.capabilities.decide ? "Available" : "Unknown"}
              </div>
              <p className="ws-verdict-detail">
                Admin-key gated. A 401/403 means the proxy is not authorized.
              </p>
            </div>
          </div>
          <div className="ws-banner is-purple mt-3">
            <KeyRound className="mt-0.5 h-4 w-4 shrink-0" />
            <div>
              <strong>Approval is not standing access.</strong> Approving authorizes
              this call ID and its argument hash once. The next call needs its own
              decision, even if the tool and arguments look identical.
            </div>
          </div>
        </CardBody>
      </Card>

      <div className="ws-grid ws-grid-sidebar">
        <Card>
          <CardHead
            title="Pending queue"
            subtitle="Newest held call first · re-read after every decision"
            icon={UserCheck}
            actions={
              <span className="ws-count-pill">{pending.length} pending</span>
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
                  placeholder="Call ID, tool, source or reason"
                  aria-label="Search pending approvals"
                />
              </span>
            </label>
            <span className="ws-count-pill">
              {filteredPending.length} / {pending.length}
            </span>
            {search ? (
              <button
                type="button"
                className="ws-btn is-xs is-ghost"
                onClick={() => setSearch("")}
              >
                <FilterX className="h-3 w-3" /> Clear
              </button>
            ) : null}
          </div>

          {approvals.isLoading ? (
            <CardBody>
              <LoadingState rows={3} />
            </CardBody>
          ) : approvals.failure && !approvals.data ? (
            <CardBody>
              <ErrorState failure={approvals.failure} onRetry={refresh} />
            </CardBody>
          ) : filteredPending.length ? (
            <div className="ws-table-wrap">
              <table className="ws-table">
                <thead>
                  <tr>
                    <th>Held</th>
                    <th>Tool</th>
                    <th>Source</th>
                    <th>Why held</th>
                    <th>Call ID</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredPending.map((entry) => (
                    <tr
                      key={entry.call_id}
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
                      aria-label={`Inspect held call ${entry.call_id}`}
                    >
                      <td className="is-nowrap text-[10.5px] text-[#6f6c66]">
                        {formatRelative(entry.ts)}
                      </td>
                      <td className="font-mono text-[10.5px]">{entry.tool}</td>
                      <td>
                        <SourceBadge source={entry.source} />
                      </td>
                      <td className="max-w-[280px] text-[10.5px] text-[#4d4a45]">
                        <span className="line-clamp-2">
                          {entry.reasons[0]?.detail ?? "Held by policy."}
                        </span>
                      </td>
                      <td>
                        <button
                          type="button"
                          className="ws-link font-mono text-[9.5px]"
                          onClick={(event) => {
                            event.stopPropagation();
                            setSelectedCall(entry.call_id);
                          }}
                        >
                          {entry.call_id}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : pending.length ? (
            <EmptyState
              title="No pending calls match this search."
              description="Clear the search to see the full queue."
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
              title="No calls are waiting for a human."
              description="The queue is clear. Held calls appear here only after the gateway evaluates a call and policy returns require_approval."
              icon={ShieldCheck}
            />
          )}
        </Card>

        <div className="ws-detail">
          <Card>
            <CardHead
              title="Decision panel"
              subtitle="Exact call, arguments and policy reasons"
              icon={KeyRound}
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
                  <div className="ws-between">
                    <DecisionBadge decision={selected.decision} />
                    <SourceBadge source={selected.source} />
                  </div>
                  <KeyValue
                    items={[
                      { label: "Tool", value: selected.tool, mono: true },
                      { label: "Call ID", value: selected.call_id, mono: true },
                      { label: "Time", value: formatTimestamp(selected.ts) },
                      { label: "Age", value: formatRelative(selected.ts) },
                      {
                        label: "Args hash",
                        value: selected.args_hash ?? "not recorded",
                        mono: true,
                      },
                      {
                        label: "Approval",
                        value: selected.approval ?? (isPending ? "pending" : "—"),
                      },
                      ...(selected.approval_of
                        ? [
                            {
                              label: "Approval of",
                              value: selected.approval_of,
                              mono: true,
                            },
                          ]
                        : []),
                      ...(selected.consumed_by
                        ? [
                            {
                              label: "Consumed by",
                              value: selected.consumed_by,
                              mono: true,
                            },
                          ]
                        : []),
                    ]}
                  />
                  <div>
                    <span className="ws-label">Policy reasons</span>
                    <ReasonList reasons={selected.reasons ?? []} />
                  </div>
                  <JsonBlock
                    value={selected.arguments ?? {}}
                    title="Arguments · bound by hash"
                    collapsedLines={10}
                  />
                  <DetectionList detections={selected.detections ?? []} compact />

                  {isPending ? (
                    <div className="ws-stack-sm">
                      <label className="ws-field">
                        <span className="ws-label">Approver label</span>
                        <input
                          className="ws-input"
                          value={approver}
                          onChange={(event) => setApprover(event.target.value)}
                          maxLength={120}
                          autoComplete="off"
                        />
                        <span className="ws-hint">
                          Recorded in the append-only approval entry. Use a real
                          operator identity.
                        </span>
                      </label>
                      <div className="ws-grid ws-grid-2">
                        <button
                          type="button"
                          className="ws-btn is-lime is-sm"
                          onClick={() => {
                            setFailure(null);
                            setSuccess(null);
                            setPendingVerdict("approve");
                          }}
                          disabled={submitting || !approver.trim()}
                        >
                          <Check className="h-3.5 w-3.5" /> Approve once
                        </button>
                        <button
                          type="button"
                          className="ws-btn is-danger is-sm"
                          onClick={() => {
                            setFailure(null);
                            setSuccess(null);
                            setPendingVerdict("deny");
                          }}
                          disabled={submitting || !approver.trim()}
                        >
                          <X className="h-3.5 w-3.5" /> Deny
                        </button>
                      </div>
                    </div>
                  ) : (
                    <div className="ws-banner">
                      <Clock3 className="mt-0.5 h-4 w-4 shrink-0" />
                      <div>
                        This record is no longer pending. Decisions are immutable and
                        are never changed locally.
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <EmptyState
                  title="Select a held call."
                  description="Choose a row in the pending queue to inspect its exact arguments, hash and reasons before deciding."
                  icon={UserCheck}
                />
              )}
            </CardBody>
          </Card>
        </div>
      </div>

      <Card>
        <CardHead
          title="Recent human decisions"
          subtitle="Append-only approval entries · newest first"
          icon={ShieldCheck}
          actions={
            <Link href="/workspace/audit" className="ws-link">
              Full audit <ArrowUpRight className="h-3 w-3" />
            </Link>
          }
        />
        <CardBody flush>
          {recent.length ? (
            <div className="ws-table-wrap">
              <table className="ws-table">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Decision</th>
                    <th>Tool</th>
                    <th>Approval of</th>
                    <th>Args hash</th>
                    <th>Consumed by</th>
                    <th>Entry call ID</th>
                  </tr>
                </thead>
                <tbody>
                  {recent.map((entry) => (
                    <tr
                      key={`${entry.call_id}-${String(entry.ts)}`}
                      className="is-clickable"
                      onClick={() => setSelectedCall(entry.call_id)}
                      tabIndex={0}
                      onKeyDown={(event) => {
                        if (event.key === "Enter" || event.key === " ") {
                          event.preventDefault();
                          setSelectedCall(entry.call_id);
                        }
                      }}
                    >
                      <td className="is-nowrap text-[10.5px] text-[#6f6c66]">
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
                      <td className="font-mono text-[10.5px]">{entry.tool}</td>
                      <td className="font-mono text-[9.5px]">
                        {entry.approval_of ?? "—"}
                      </td>
                      <td className="font-mono text-[9.5px]">
                        {entry.args_hash ?? "—"}
                      </td>
                      <td className="font-mono text-[9.5px]">
                        {entry.consumed_by ?? "—"}
                      </td>
                      <td className="font-mono text-[9.5px]">{entry.call_id}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <EmptyState
              title="No human decisions recorded."
              description="Approved, rejected and consumed entries appear here after the gateway appends them."
              icon={Clock3}
            />
          )}
        </CardBody>
      </Card>

      <Banner tone="purple" icon={KeyRound}>
        <strong>Server-side authorization.</strong> The browser never receives the
        gateway admin key. The Next.js proxy attaches it to{" "}
        <code className="ws-mono">POST /v1/approvals/{"{call_id}"}</code>. A 403 means
        the proxy environment is missing or misconfigured, not that the decision was
        partially applied.
      </Banner>

      <ConfirmDialog
        open={pendingVerdict !== null}
        title={pendingVerdict === "approve" ? "Approve this call once?" : "Deny this call?"}
        description={
          selected ? (
            <>
              <p>
                <strong>{selected.tool}</strong> · call{" "}
                <code className="ws-mono">{selected.call_id}</code>
              </p>
              <p className="mt-2">
                {pendingVerdict === "approve"
                  ? "This authorizes the exact call and argument hash once. It does not grant permanent or standing access to the tool."
                  : "The call will not execute. The rejection is appended to the audit trail and cannot be undone."}
              </p>
              <p className="mt-2">
                Approver: <strong>{approver || "—"}</strong>
              </p>
            </>
          ) : null
        }
        confirmLabel={pendingVerdict === "approve" ? "Approve once" : "Deny call"}
        tone={pendingVerdict === "approve" ? "primary" : "danger"}
        pending={submitting}
        confirmDisabled={!approver.trim()}
        onConfirm={() => void decide()}
        onCancel={() => {
          if (!submitting) setPendingVerdict(null);
        }}
      />
    </div>
  );
}
