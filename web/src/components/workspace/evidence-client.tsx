"use client";

import {
  AlertTriangle,
  Archive,
  BadgeCheck,
  CheckCircle2,
  FileCheck2,
  GitBranch,
  RefreshCw,
  ScrollText,
  ShieldAlert,
  ShieldCheck,
  Terminal,
} from "lucide-react";
import { useMemo, useState } from "react";
import {
  formatDate,
  formatNumber,
  formatTimestamp,
} from "@/lib/api/format";
import type {
  EvidenceReport,
  EvidenceReportsResponse,
  EvidenceResponse,
} from "@/lib/api/types";
import { useLiveData } from "@/lib/hooks/use-live-data";
import { cn } from "@/lib/utils";
import { CodeBlock } from "@/components/workspace/json-block";
import {
  Banner,
  Card,
  CardBody,
  CardHead,
  DecisionBadge,
  EmptyState,
  ErrorState,
  KeyValue,
  LiveMeta,
  LoadingState,
  PageHeader,
  StatCard,
  StatusBadge,
} from "@/components/workspace/ui";

function statusTone(status: string): "ok" | "warn" | "error" | "neutral" {
  if (status.includes("error") || status.includes("mismatch") || status.includes("fail")) {
    return "error";
  }
  if (status.includes("warn") || status.includes("findings") || status.includes("unavailable")) {
    return "warn";
  }
  if (status.includes("ok") || status.includes("pass") || status.includes("clean")) {
    return "ok";
  }
  return "neutral";
}

function formatBytes(bytes: number | undefined): string {
  if (bytes === undefined) return "—";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export function EvidenceClient() {
  const [tab, setTab] = useState<"all" | "historical" | "live">("all");
  const reports = useLiveData<EvidenceReportsResponse>("/v1/evidence/reports", {
    intervalMs: 60_000,
  });
  const evidence = useLiveData<EvidenceResponse>("/v1/evidence?limit=10", {
    intervalMs: 30_000,
  });

  const allReports = useMemo(() => reports.data?.reports ?? [], [reports.data]);
  const historical = allReports.filter((report) => !report.live);
  const live = allReports.filter((report) => report.live);
  const visible =
    tab === "historical" ? historical : tab === "live" ? live : allReports;

  const baseline = reports.data?.baseline;

  return (
    <div className="ws-stack">
      <PageHeader
        eyebrow="Security evidence"
        title={
          <>
            Recorded proof, <em>live state.</em>
          </>
        }
        description="Committed artifacts and live gateway values are shown separately. A historical test or scan is never presented as freshly executed. Every card names its source, recorded commit/date and the command used to reproduce it."
        actions={
          <button
            type="button"
            className="ws-btn is-sm"
            onClick={() => {
              void Promise.all([reports.refresh(), evidence.refresh()]);
            }}
            disabled={reports.isRefreshing || evidence.isRefreshing}
          >
            <RefreshCw
              className={cn(
                "h-3.5 w-3.5",
                (reports.isRefreshing || evidence.isRefreshing) && "animate-spin",
              )}
            />
            {reports.isRefreshing || evidence.isRefreshing ? "Refreshing" : "Refresh"}
          </button>
        }
      />

      {reports.failure && reports.data ? (
        <Banner tone="warn" icon={AlertTriangle}>
          <strong>Evidence refresh failed.</strong> Showing the last successful manifest.{" "}
          {reports.failure.message}
        </Banner>
      ) : null}

      <Banner tone="purple" icon={Archive}>
        <strong>Historical ≠ fresh.</strong>{" "}
        {reports.data?.notes.freshness ??
          "Historic reports display their recorded commit/date. Runtime reports are fetched live and labelled Live."}{" "}
        {reports.data?.notes.claims ?? ""}
      </Banner>

      <div className="ws-grid ws-grid-4">
        <StatCard
          label="Historical artifacts"
          value={reports.data ? formatNumber(historical.length) : "—"}
          meta="Recorded runs · not re-executed"
          icon={Archive}
        />
        <StatCard
          label="Live runtime reports"
          value={reports.data ? formatNumber(live.length) : "—"}
          meta="Fetched from the running gateway"
          icon={ShieldCheck}
          tone="lime"
        />
        <StatCard
          label="Semgrep findings"
          value={baseline ? formatNumber(baseline.semgrep_findings) : "—"}
          meta={baseline ? `${baseline.semgrep_rules} documented rules` : "From the committed artifact"}
          icon={FileCheck2}
        />
        <StatCard
          label="Recorded pytest"
          value={baseline ? baseline.pytest : "—"}
          meta="Historic · reproduce with the command"
          icon={BadgeCheck}
          tone="purple"
        />
      </div>

      <div className="ws-grid ws-grid-main">
        <Card>
          <CardHead
            title="Evidence manifest"
            subtitle={
              reports.data
                ? `Repository ${reports.data.repo.branch ?? "unknown branch"} · commit ${reports.data.repo.commit?.slice(0, 12) ?? "unknown"}`
                : "GET /v1/evidence/reports"
            }
            icon={BadgeCheck}
            actions={
              reports.lastUpdated ? (
                <LiveMeta
                  lastUpdated={reports.lastUpdated}
                  isRefreshing={reports.isRefreshing}
                  isStale={reports.isStale}
                  intervalLabel="60s"
                />
              ) : null
            }
          />
          <div className="ws-tabs px-[17px]">
            {(
              [
                ["all", `All (${allReports.length})`],
                ["historical", `Historical (${historical.length})`],
                ["live", `Live (${live.length})`],
              ] as const
            ).map(([value, label]) => (
              <button
                key={value}
                type="button"
                className={cn("ws-tab", tab === value && "is-active")}
                onClick={() => setTab(value)}
                aria-pressed={tab === value}
              >
                {label}
              </button>
            ))}
          </div>
          <CardBody>
            {reports.isLoading ? (
              <LoadingState rows={3} />
            ) : reports.failure && !reports.data ? (
              <ErrorState failure={reports.failure} onRetry={() => void reports.refresh()} />
            ) : visible.length ? (
              <div className="ws-stack">
                {visible.map((report) => (
                  <ReportCard key={report.id} report={report} />
                ))}
              </div>
            ) : (
              <EmptyState
                title="No reports in this category."
                description="Switch tabs or refresh the manifest."
                icon={ScrollText}
              />
            )}
          </CardBody>
        </Card>

        <div className="ws-detail">
          <Card>
            <CardHead
              title="Live evidence snapshot"
              subtitle="GET /v1/evidence · current gateway state"
              icon={ShieldCheck}
              actions={
                evidence.data ? (
                  <StatusBadge tone="ok">live</StatusBadge>
                ) : evidence.failure ? (
                  <StatusBadge tone="error">offline</StatusBadge>
                ) : null
              }
            />
            <CardBody>
              {evidence.data ? (
                <div className="ws-stack">
                  <KeyValue
                    items={[
                      {
                        label: "Health",
                        value: (
                          <span className="flex items-center gap-2">
                            <StatusBadge tone="ok">{evidence.data.health.status}</StatusBadge>
                            <span className="text-[10px]">
                              {evidence.data.health.detectors.join(", ")}
                            </span>
                          </span>
                        ),
                      },
                      {
                        label: "Enforcement",
                        value: (
                          <StatusBadge tone={evidence.data.enforced ? "ok" : "warn"}>
                            {evidence.data.enforced ? "ON" : "OFF"}
                          </StatusBadge>
                        ),
                      },
                      {
                        label: "Provenance",
                        value: evidence.data.provenance_dev_mode ? (
                          <StatusBadge tone="warn">dev mode</StatusBadge>
                        ) : (
                          <StatusBadge tone="ok">HMAC enforced</StatusBadge>
                        ),
                      },
                      ...(evidence.data.manifest_enforced === undefined ||
                      evidence.data.manifest_enforced === null
                        ? []
                        : [
                            {
                              label: "Manifest",
                              value: (
                                <StatusBadge
                                  tone={evidence.data.manifest_enforced ? "ok" : "warn"}
                                >
                                  {evidence.data.manifest_enforced ? "enforced" : "disabled"}
                                </StatusBadge>
                              ),
                            },
                          ]),
                      {
                        label: "Auth",
                        value: evidence.data.health.auth_required
                          ? "API key required"
                          : "open dev gateway",
                      },
                      {
                        label: "Entries read",
                        value: formatNumber(evidence.data.entries.length),
                      },
                      {
                        label: "Fetched",
                        value: formatTimestamp(evidence.lastUpdated),
                      },
                    ]}
                  />
                  {evidence.data.provenance_dev_mode ? (
                    <div className="ws-banner is-warn">
                      <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
                      <div>
                        Provenance dev mode is active: self-asserted sources are
                        honored. Set AGENTSHIELD_HARNESS_SECRET before exposing the
                        gateway.
                      </div>
                    </div>
                  ) : null}
                  <div>
                    <span className="ws-label">Latest live entries</span>
                    <div className="ws-stack-sm mt-1.5">
                      {evidence.data.entries.slice(0, 5).map((entry) => (
                        <div
                          key={entry.call_id}
                          className="flex items-center justify-between gap-2 rounded-[9px] border border-[#e9e6e0] bg-[#fbfaf7] px-2.5 py-2"
                        >
                          <span className="min-w-0">
                            <span className="block truncate font-mono text-[10px]">
                              {entry.tool}
                            </span>
                            <span className="block truncate text-[9px] text-[#8b8881]">
                              {formatTimestamp(entry.ts)} · {entry.call_id}
                            </span>
                          </span>
                          <DecisionBadge decision={entry.decision} short />
                        </div>
                      ))}
                      {!evidence.data.entries.length ? (
                        <p className="ws-hint">No audit entries returned.</p>
                      ) : null}
                    </div>
                  </div>
                </div>
              ) : evidence.failure ? (
                <ErrorState
                  failure={evidence.failure}
                  onRetry={() => void evidence.refresh()}
                  compact
                />
              ) : (
                <LoadingState rows={2} />
              )}
            </CardBody>
          </Card>

          <Card>
            <CardHead
              title="Baseline"
              subtitle="Values read from the evidence manifest"
              icon={Terminal}
            />
            <CardBody>
              {baseline ? (
                <KeyValue
                  items={[
                    { label: "Pytest", value: baseline.pytest },
                    { label: "Semgrep rules", value: formatNumber(baseline.semgrep_rules) },
                    {
                      label: "Semgrep findings",
                      value: formatNumber(baseline.semgrep_findings),
                    },
                    { label: "RAG beats", value: formatNumber(baseline.rag_beats) },
                    { label: "Corpus docs", value: formatNumber(baseline.corpus_docs) },
                    {
                      label: "Ledger rows",
                      value: formatNumber(baseline.red_team_ledger_rows),
                    },
                  ]}
                />
              ) : (
                <LoadingState rows={2} />
              )}
            </CardBody>
          </Card>
        </div>
      </div>

      <Banner tone="purple" icon={GitBranch}>
        <strong>Reproducibility.</strong> Commands shown on each card are the recorded
        reproduction commands, not actions this page can run. The console has no
        arbitrary-command endpoint by design.
      </Banner>
    </div>
  );
}

function ReportCard({ report }: { report: EvidenceReport }) {
  return (
    <div className="ws-doc">
      <div className="ws-between">
        <div className="ws-wrap">
          <span className="ws-doc-id">{report.title}</span>
          <StatusBadge tone={statusTone(report.status)}>
            {report.status_label}
          </StatusBadge>
          <span className="ws-badge is-neutral">{report.category}</span>
          {report.live ? (
            <span className="ws-badge is-lime">live</span>
          ) : (
            <span className="ws-badge is-purple">historical</span>
          )}
        </div>
        <span className="font-mono text-[11px] font-semibold">{report.value}</span>
      </div>

      <p className="ws-doc-text mt-2">{report.detail}</p>

      <div className="ws-doc-meta">
        <span>source: {report.source}</span>
        {report.recorded_commit ? <span>commit: {report.recorded_commit}</span> : null}
        {report.recorded_date ? (
          <span>recorded: {formatDate(report.recorded_date)}</span>
        ) : null}
        {report.live ? <span>fetched live</span> : <span>not re-executed</span>}
      </div>

      {report.artifacts.length ? (
        <div className="mt-3">
          <span className="ws-label">Artifacts</span>
          <div className="ws-stack-sm mt-1.5">
            {report.artifacts.map((artifact) => (
              <div
                key={artifact.path}
                className="flex items-center justify-between gap-2 rounded-[9px] border border-[#e9e6e0] bg-[#fbfaf7] px-2.5 py-2 text-[10px]"
              >
                <span className="flex min-w-0 items-center gap-2">
                  {artifact.available ? (
                    <CheckCircle2 className="h-3.5 w-3.5 shrink-0 text-[#2e5209]" />
                  ) : (
                    <AlertTriangle className="h-3.5 w-3.5 shrink-0 text-[#7a5300]" />
                  )}
                  <span className="ws-truncate font-mono">{artifact.path}</span>
                </span>
                <span className="shrink-0 font-mono text-[9px] text-[#6f6c66]">
                  {artifact.available
                    ? `${formatBytes(artifact.bytes)} · ${formatTimestamp(artifact.updated_at)}`
                    : "unavailable"}
                </span>
              </div>
            ))}
          </div>
        </div>
      ) : null}

      {report.semgrep ? (
        <div className="ws-wrap mt-3">
          <span className="ws-badge is-neutral">
            semgrep {report.semgrep.version ?? "unknown"}
          </span>
          <span className="ws-badge is-neutral">
            {report.semgrep.paths_scanned ?? 0} paths
          </span>
          <span className="ws-badge is-neutral">
            {report.semgrep.errors ?? 0} errors
          </span>
        </div>
      ) : null}

      {report.ledger ? (
        <div className="ws-wrap mt-3">
          {Object.entries(report.ledger.by_status).map(([key, value]) => (
            <span key={key} className="ws-badge is-neutral">
              {key}: {value}
            </span>
          ))}
          {Object.entries(report.ledger.by_severity).map(([key, value]) => (
            <span key={key} className="ws-badge is-neutral">
              {key}: {value}
            </span>
          ))}
        </div>
      ) : null}

      {report.health ? (
        <div className="ws-wrap mt-3">
          <StatusBadge tone="ok">{report.health.status}</StatusBadge>
          {report.health.detectors.map((detector) => (
            <span key={detector} className="ws-badge is-neutral">
              {detector}
            </span>
          ))}
          <span className="ws-badge is-neutral">
            auth {report.health.auth_required ? "required" : "open"}
          </span>
        </div>
      ) : null}

      {report.enforced !== undefined ? (
        <div className="ws-wrap mt-3">
          <StatusBadge tone={report.enforced ? "ok" : "warn"}>
            enforcement {report.enforced ? "ON" : "OFF"}
          </StatusBadge>
          {report.provenance_dev_mode !== undefined ? (
            <StatusBadge tone={report.provenance_dev_mode ? "warn" : "ok"}>
              provenance {report.provenance_dev_mode ? "dev mode" : "HMAC"}
            </StatusBadge>
          ) : null}
          {report.integrity_verified !== undefined ? (
            <StatusBadge
              tone={
                report.integrity_verified
                  ? "ok"
                  : report.integrity_verified === null
                    ? "warn"
                    : "error"
              }
            >
              integrity{" "}
              {report.integrity_verified
                ? "verified"
                : report.integrity_verified === null
                  ? "pin not set"
                  : "mismatch"}
            </StatusBadge>
          ) : null}
        </div>
      ) : null}

      <p className="ws-hint mt-3">{report.note}</p>
      <div className="mt-2">
        <CodeBlock code={report.command} label="Reproduce" />
      </div>
    </div>
  );
}
