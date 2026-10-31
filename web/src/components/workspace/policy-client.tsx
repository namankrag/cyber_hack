"use client";

import {
  AlertTriangle,
  CheckCircle2,
  FileCode2,
  Fingerprint,
  Layers,
  LockKeyhole,
  RefreshCw,
  Scale,
  Search,
  ShieldAlert,
  ShieldCheck,
  Wrench,
} from "lucide-react";
import { useMemo, useState } from "react";
import {
  formatNumber,
  formatTimestamp,
  titleCase,
} from "@/lib/api/format";
import type { PolicyResponse } from "@/lib/api/types";
import { useLiveData } from "@/lib/hooks/use-live-data";
import { cn } from "@/lib/utils";
import { CodeBlock } from "@/components/workspace/json-block";
import {
  Banner,
  Card,
  CardBody,
  CardHead,
  EmptyState,
  ErrorState,
  KeyValue,
  LiveMeta,
  LoadingState,
  PageHeader,
  PolicyStep,
  StatCard,
  StatusBadge,
} from "@/components/workspace/ui";

export function PolicyClient() {
  const [search, setSearch] = useState("");
  const policy = useLiveData<PolicyResponse>("/v1/policy", { intervalMs: 30_000 });

  const tools = useMemo(() => policy.data?.tools ?? [], [policy.data]);
  const filteredTools = useMemo(() => {
    const term = search.trim().toLowerCase();
    if (!term) return tools;
    return tools.filter((tool) =>
      [
        tool.name,
        tool.sensitivity,
        tool.decision_requirement,
        ...tool.allow_sources,
      ]
        .join(" ")
        .toLowerCase()
        .includes(term),
    );
  }, [search, tools]);

  const data = policy.data;
  const integrityTone = !data
    ? "neutral"
    : data.integrity_verified === true
      ? "ok"
      : data.digest_pinned
        ? "error"
        : "warn";
  const integrityLabel = !data
    ? "unknown"
    : data.integrity_verified === true
      ? "verified"
      : data.digest_pinned
        ? "mismatch"
        : "pin not set";

  return (
    <div className="ws-stack">
      <PageHeader
        eyebrow="Policy manager"
        title={
          <>
            The rules, <em>exactly as loaded.</em>
          </>
        }
        description="A read-only view of the active YAML policy, its defaults, per-tool permissions, evaluation order and SHA-256 digest. This build has no authenticated publish endpoint, so there is deliberately no edit control."
        actions={
          <>
            <StatusBadge tone="purple">
              <LockKeyhole className="h-3 w-3" /> read-only
            </StatusBadge>
            <button
              type="button"
              className="ws-btn is-sm"
              onClick={() => void policy.refresh()}
              disabled={policy.isRefreshing}
            >
              <RefreshCw
                className={cn("h-3.5 w-3.5", policy.isRefreshing && "animate-spin")}
              />
              {policy.isRefreshing ? "Refreshing" : "Refresh"}
            </button>
          </>
        }
      />

      {policy.failure && policy.data ? (
        <Banner tone="warn" icon={AlertTriangle}>
          <strong>Live updates interrupted.</strong> Showing the last successful policy
          snapshot. {policy.failure.message}
        </Banner>
      ) : null}

      <Banner tone="purple" icon={LockKeyhole}>
        <strong>Read-only by design.</strong>{" "}
        {data?.notes.write ??
          "Policy editing is disabled: no authenticated publish endpoint exists. Change the policy file on the gateway host through your reviewed deployment process."}
      </Banner>

      <div className="ws-grid ws-grid-4">
        <StatCard
          loading={!policy.data && !policy.failure}
          label="Policy"
          value={data ? `v${data.version}` : "—"}
          meta={data ? data.name : policy.failure ? "Gateway unreachable \u2014 retry" : "Loading\u2026"}
          icon={Scale}
        />
        <StatCard
          loading={!policy.data && !policy.failure}
          label="Governed tools"
          value={data ? formatNumber(data.tool_count) : "—"}
          meta="Declared tool rules"
          icon={Wrench}
          tone="lime"
        />
        <StatCard
          loading={!policy.data && !policy.failure}
          label="Digest pinned"
          value={data ? (data.digest_pinned ? "Yes" : "No") : "—"}
          meta={
            data
              ? data.digest_pinned
                ? "AGENTSHIELD_POLICY_SHA256 is set"
                : "Trust root is in dev mode"
              : policy.failure ? "Gateway unreachable \u2014 retry" : "Loading\u2026"
          }
          icon={Fingerprint}
          tone={data && !data.digest_pinned ? "purple" : undefined}
        />
        <StatCard
          loading={!policy.data && !policy.failure}
          label="Integrity"
          value={data ? integrityLabel : "—"}
          meta={data?.notes.integrity ?? "Comparing digest with expected pin"}
          icon={integrityTone === "ok" ? ShieldCheck : ShieldAlert}
        />
      </div>

      <div className="ws-grid ws-grid-main">
        <Card>
          <CardHead
            title="Active policy YAML"
            subtitle={
              data
                ? `${data.path} · ${data.yaml.split("\n").length} lines · loaded ${formatTimestamp(data.loaded_at)}`
                : "GET /v1/policy"
            }
            icon={FileCode2}
            actions={
              policy.lastUpdated ? (
                <LiveMeta
                  lastUpdated={policy.lastUpdated}
                  isRefreshing={policy.isRefreshing}
                  isStale={policy.isStale}
                  intervalLabel="30s"
                />
              ) : null
            }
          />
          <CardBody>
            {policy.isLoading ? (
              <LoadingState rows={2} />
            ) : policy.failure && !data ? (
              <ErrorState failure={policy.failure} onRetry={policy.refresh} />
            ) : data ? (
              data.yaml ? (
                <CodeBlock
                  code={data.yaml}
                  label="Loaded from disk · not editable here"
                />
              ) : (
                <EmptyState
                  title="Policy YAML was not readable."
                  description="The gateway returned policy metadata but no YAML text. Check the policy path and file permissions on the gateway host."
                  icon={FileCode2}
                />
              )
            ) : null}
          </CardBody>
        </Card>

        <div className="ws-detail">
          <Card>
            <CardHead
              title="Integrity & provenance"
              subtitle="Computed from the exact file the gateway loaded"
              icon={Fingerprint}
              actions={
                <StatusBadge tone={integrityTone}>{integrityLabel}</StatusBadge>
              }
            />
            <CardBody>
              {data ? (
                <div className="ws-stack">
                  <KeyValue
                    items={[
                      { label: "Name", value: data.name, mono: true },
                      { label: "Path", value: data.path, mono: true },
                      { label: "Version", value: String(data.version) },
                      { label: "Digest", value: data.digest ?? "unavailable", mono: true },
                      {
                        label: "Expected",
                        value: data.expected_digest ?? "not configured",
                        mono: true,
                      },
                      {
                        label: "Updated",
                        value: formatTimestamp(data.updated_at),
                      },
                      {
                        label: "Loaded",
                        value: formatTimestamp(data.loaded_at),
                      },
                    ]}
                  />
                  {data.integrity_verified === true ? (
                    <div className="ws-banner is-purple">
                      <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" />
                      <div>
                        The computed digest matches the configured pin. This proves the
                        loaded file matches the reviewed digest, not that the rules are
                        correct.
                      </div>
                    </div>
                  ) : data.digest_pinned ? (
                    <div className="ws-banner is-error">
                      <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
                      <div>
                        The computed digest does not match the configured pin. Treat the
                        policy as untrusted until the mismatch is investigated.
                      </div>
                    </div>
                  ) : (
                    <div className="ws-banner is-warn">
                      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                      <div>
                        No policy digest is pinned. The gateway reports the computed
                        digest but cannot verify it against a reviewed value.
                      </div>
                    </div>
                  )}
                </div>
              ) : policy.failure ? (
                <ErrorState failure={policy.failure} onRetry={policy.refresh} compact />
              ) : (
                <LoadingState rows={2} />
              )}
            </CardBody>
          </Card>

          <Card>
            <CardHead
              title="Policy defaults"
              subtitle="Applied when no tool rule is more specific"
              icon={Scale}
            />
            <CardBody>
              {data ? (
                <KeyValue
                  items={[
                    { label: "Unknown tool", value: data.defaults.unknown_tool },
                    {
                      label: "Detector threat · high",
                      value: data.defaults.on_detector_threat_high_sensitivity,
                    },
                    {
                      label: "Detector threat · low",
                      value: data.defaults.on_detector_threat_low_sensitivity,
                    },
                    {
                      label: "Untrusted · high",
                      value: data.defaults.on_untrusted_high_sensitivity,
                    },
                    {
                      label: "Untrusted · low",
                      value: data.defaults.on_untrusted_low_sensitivity,
                    },
                    {
                      label: "Detector error",
                      value: data.defaults.detector_error_decision,
                    },
                    {
                      label: "Fail closed",
                      value: data.defaults.fail_closed_on_detector_error
                        ? "yes"
                        : "no",
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

      <Card>
        <CardHead
          title="Tool permissions"
          subtitle="Per-tool rules as loaded · source allow-lists and approval requirements"
          icon={Wrench}
          actions={<span className="ws-count-pill">{tools.length} tools</span>}
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
                placeholder="Tool, sensitivity, source or requirement"
                aria-label="Search policy tools"
              />
            </span>
          </label>
          <span className="ws-count-pill">
            {filteredTools.length} / {tools.length}
          </span>
        </div>
        <CardBody flush>
          {data ? (
            filteredTools.length ? (
              <div className="ws-table-wrap">
                <table className="ws-table">
                  <thead>
                    <tr>
                      <th>Tool</th>
                      <th>Sensitivity</th>
                      <th>Enabled</th>
                      <th>Approval</th>
                      <th>Allowed sources</th>
                      <th>On disallowed source</th>
                      <th>Requirement</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredTools.map((tool) => (
                      <tr key={tool.name}>
                        <td className="font-mono ws-fs-body font-semibold">
                          {tool.name}
                        </td>
                        <td>
                          <StatusBadge
                            tone={tool.sensitivity === "high" ? "warn" : "neutral"}
                          >
                            {tool.sensitivity}
                          </StatusBadge>
                        </td>
                        <td>
                          {tool.allow ? (
                            <StatusBadge tone="ok">yes</StatusBadge>
                          ) : (
                            <StatusBadge tone="error">no</StatusBadge>
                          )}
                        </td>
                        <td>
                          {tool.require_approval ? (
                            <StatusBadge tone="warn">required</StatusBadge>
                          ) : (
                            <StatusBadge tone="neutral">no</StatusBadge>
                          )}
                        </td>
                        <td className="ws-fs-body">
                          {tool.allow_sources.length
                            ? tool.allow_sources.join(", ")
                            : "any"}
                        </td>
                        <td className="ws-fs-body">
                          {titleCase(tool.on_disallowed_source)}
                        </td>
                        <td className="font-mono ws-fs-meta">
                          {tool.decision_requirement}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <EmptyState
                title="No tool rules match this search."
                description="Clear the search to see every governed tool."
                icon={Search}
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
            )
          ) : policy.failure ? (
            <div className="p-4">
              <ErrorState failure={policy.failure} onRetry={policy.refresh} compact />
            </div>
          ) : (
            <div className="p-4">
              <LoadingState rows={2} />
            </div>
          )}
        </CardBody>
      </Card>

      <Card>
        <CardHead
          title="Evaluation order"
          subtitle="The gateway evaluates these stages in order and keeps the most restrictive verdict"
          icon={Layers}
        />
        <CardBody>
          {data ? (
            <ol className="ws-policy-steps">
              {data.evaluation_order.map((stage) => (
                <PolicyStep
                  key={stage.step}
                  step={stage.step}
                  label={stage.label}
                  description={stage.description}
                  rule={stage.rule}
                />
              ))}
            </ol>
          ) : (
            <LoadingState rows={2} />
          )}
        </CardBody>
      </Card>
    </div>
  );
}
