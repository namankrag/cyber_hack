"use client";

import {
  AlertTriangle,
  Clock3,
  FlaskConical,
  GitCompare,
  History,
  Play,
  RefreshCw,
  RotateCcw,
  ShieldCheck,
  Swords,
  Terminal,
} from "lucide-react";
import { useMemo, useState, type FormEvent } from "react";
import { apiPost } from "@/lib/api/client";
import { toApiFailure, type ApiFailure } from "@/lib/api/errors";
import {
  formatDurationMs,
  formatTimestamp,
  sourceLabel,
} from "@/lib/api/format";
import type {
  AuditEntry,
  EnforceResponse,
  RedteamHistoryResponse,
  RedteamRunResponse,
  RedteamScenario,
  RedteamScenariosResponse,
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
  LoadingState,
  PageHeader,
  ReasonList,
  SourceBadge,
  StageList,
  StatusBadge,
  SuccessNote,
} from "@/components/workspace/ui";

interface PayloadForm {
  tool_name: string;
  source: string;
  argumentsText: string;
  context: string;
}

const emptyForm: PayloadForm = {
  tool_name: "",
  source: "untrusted",
  argumentsText: "{}",
  context: "",
};

function formFromScenario(scenario: RedteamScenario): PayloadForm {
  return {
    tool_name: scenario.tool_name,
    source: scenario.source,
    argumentsText: JSON.stringify(scenario.arguments, null, 2),
    context: scenario.context,
  };
}

export function RedteamClient() {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [draft, setDraft] = useState<PayloadForm | null>(null);
  const [dirty, setDirty] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [failure, setFailure] = useState<ApiFailure | null>(null);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<RedteamRunResponse | null>(null);
  const [historyCall, setHistoryCall] = useState<string | null>(null);

  const scenarios = useLiveData<RedteamScenariosResponse>("/v1/redteam/scenarios", {
    intervalMs: 60_000,
  });
  const history = useLiveData<RedteamHistoryResponse>("/v1/redteam/history?limit=20", {
    intervalMs: 20_000,
  });
  const enforce = useLiveData<EnforceResponse>("/v1/enforce", { intervalMs: 15_000 });

  const scenarioList = useMemo(() => scenarios.data?.scenarios ?? [], [scenarios.data]);
  const selected = useMemo(
    () => scenarioList.find((scenario) => scenario.id === selectedId) ?? scenarioList[0] ?? null,
    [scenarioList, selectedId],
  );

  // Derive the form from the selected scenario until the operator edits it.
  // This avoids a synchronous state write when the scenario list first loads.
  const form = draft ?? (selected ? formFromScenario(selected) : emptyForm);

  const historyEntries = history.data?.entries ?? [];
  const selectedHistory =
    historyEntries.find((entry) => entry.call_id === historyCall) ?? null;

  const chooseScenario = (scenario: RedteamScenario) => {
    setSelectedId(scenario.id);
    setDraft(null);
    setDirty(false);
    setFormError(null);
    setFailure(null);
  };

  const updateForm = (patch: Partial<PayloadForm>) => {
    setDraft((current) => ({ ...(current ?? form), ...patch }));
    setDirty(true);
  };

  const resetForm = () => {
    if (!selected) return;
    setDraft(null);
    setDirty(false);
    setFormError(null);
  };

  const run = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setFormError(null);
    setFailure(null);
    setResult(null);

    if (!selected?.id) {
      setFormError("Select a scenario first.");
      return;
    }

    setRunning(true);
    try {
      // F5: the harness executes the saved server-side scenario. Only the
      // scenario id is sent; the trust label comes from the scenario, never
      // from this browser form.
      const response = await apiPost<RedteamRunResponse>("/v1/redteam/run", {
        scenario_id: selected.id,
      });
      setResult(response);
      setHistoryCall(response.on.call_id);
      await Promise.all([history.refresh(), enforce.refresh()]);
    } catch (error) {
      setFailure(toApiFailure(error));
    } finally {
      setRunning(false);
    }
  };

  const gatewayDown = scenarios.failure && !scenarios.data && !history.data;

  return (
    <div className="ws-stack">
      <PageHeader
        eyebrow="Red team lab"
        title={
          <>
            Attack the boundary, <em>safely.</em>
          </>
        }
        description="Run a real attack payload through two fresh in-process runtimes — enforcement ON and OFF — using the active policy and detectors. The comparison is produced by the gateway, never by this UI. The global enforcement switch is never changed."
        actions={
          <>
            <StatusBadge tone={enforce.data?.enforced ? "ok" : "warn"}>
              Global switch: {enforce.data ? (enforce.data.enforced ? "ON" : "OFF") : "unknown"}
            </StatusBadge>
            <button
              type="button"
              className="ws-btn is-sm"
              onClick={() => {
                void Promise.all([scenarios.refresh(), history.refresh(), enforce.refresh()]);
              }}
              disabled={scenarios.isRefreshing || history.isRefreshing}
            >
              <RefreshCw
                className={cn(
                  "h-3.5 w-3.5",
                  (scenarios.isRefreshing || history.isRefreshing) && "animate-spin",
                )}
              />
              {scenarios.isRefreshing || history.isRefreshing ? "Refreshing" : "Refresh"}
            </button>
          </>
        }
      />

      {gatewayDown ? (
        <ErrorState failure={scenarios.failure!} onRetry={() => void scenarios.refresh()} />
      ) : null}
      {scenarios.failure && scenarios.data ? (
        <Banner tone="warn" icon={AlertTriangle}>
          <strong>Scenario refresh failed.</strong> Showing the last successful list.{" "}
          {scenarios.failure.message}
        </Banner>
      ) : null}
      {failure ? <ErrorState failure={failure} compact /> : null}
      {result ? (
        <SuccessNote>
          Run <span className="font-mono">{result.run_id}</span> completed.{" "}
          {result.global_enforcement_unchanged
            ? "The global enforcement switch was unchanged."
            : "The gateway did not confirm switch isolation."}
        </SuccessNote>
      ) : null}

      <Banner tone="purple" icon={ShieldCheck}>
        <strong>Isolated harness.</strong> Both runs write to a dedicated red-team
        audit file, not the main trail, and use fresh in-process runtimes. The run
        executes the saved server-side scenario: the trust label comes from the
        scenario, never from this browser form. In production provenance comes
        from a trusted token, never a browser claim.{" "}
        {scenarios.data?.enforcement_note ?? ""}
      </Banner>

      <div className="ws-grid ws-grid-sidebar">
        <Card>
          <CardHead
            title="Scenarios"
            subtitle="Built-in attacks mapped to real corpus documents where available"
            icon={Swords}
            actions={<span className="ws-count-pill">{scenarioList.length} scenarios</span>}
          />
          <CardBody>
            {scenarios.isLoading ? (
              <LoadingState rows={3} />
            ) : scenarios.failure && !scenarios.data ? (
              <ErrorState failure={scenarios.failure} onRetry={() => void scenarios.refresh()} />
            ) : scenarioList.length ? (
              <div className="ws-stack-sm">
                {scenarioList.map((scenario) => (
                  <button
                    key={scenario.id}
                    type="button"
                    className={cn(
                      "ws-scenario",
                      selected?.id === scenario.id && "is-active",
                    )}
                    onClick={() => chooseScenario(scenario)}
                    aria-pressed={selected?.id === scenario.id}
                  >
                    <div className="ws-between">
                      <strong>{scenario.title}</strong>
                      <DecisionBadge decision={scenario.expected_decision} short />
                    </div>
                    <span>{scenario.description}</span>
                    <span className="ws-wrap mt-1">
                      <span className="ws-badge is-neutral">{scenario.attack_type}</span>
                      <span className="ws-badge is-neutral">{scenario.tool_name}</span>
                      {scenario.tags.map((tag) => (
                        <span key={tag} className="ws-badge is-purple">
                          {tag}
                        </span>
                      ))}
                    </span>
                  </button>
                ))}
              </div>
            ) : (
              <EmptyState
                title="No scenarios returned."
                description="The admin-gated scenario endpoint returned an empty list."
                icon={FlaskConical}
              />
            )}
          </CardBody>
        </Card>

        <div className="ws-detail">
          <Card>
            <CardHead
              title="Payload inspector"
              subtitle="Edit the exact call the harness will evaluate"
              icon={Terminal}
              actions={
                selected ? (
                  <span className="ws-badge is-neutral">
                    expected {selected.expected_decision}
                  </span>
                ) : null
              }
            />
            <CardBody>
              {selected ? (
                <form className="ws-stack" onSubmit={run}>
                  <div className="ws-stack-sm">
                    <span className="ws-label">Selected scenario</span>
                    <div className="text-[13px] font-semibold tracking-[-0.02em]">
                      {selected.title}
                    </div>
                    <p className="ws-hint">{selected.description}</p>
                    <div className="ws-wrap">
                      <span className="ws-badge is-neutral">{selected.attack_type}</span>
                      {selected.doc_id ? (
                        <span className="ws-badge is-purple">
                          doc {selected.doc_id}
                        </span>
                      ) : null}
                    </div>
                  </div>

                  <div className="ws-divider" />

                  <label className="ws-field">
                    <span className="ws-label">Tool name</span>
                    <input
                      className="ws-input"
                      value={form.tool_name}
                      onChange={(event) => updateForm({ tool_name: event.target.value })}
                      autoComplete="off"
                      required
                    />
                  </label>
                  <label className="ws-field">
                    <span className="ws-label">Source</span>
                    <select
                      className="ws-select"
                      value={form.source}
                      onChange={(event) => updateForm({ source: event.target.value })}
                    >
                      {["untrusted", "user", "system", "trusted_tool"].map((value) => (
                        <option key={value} value={value}>
                          {sourceLabel(value)}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label className="ws-field">
                    <span className="ws-label">Arguments · JSON object</span>
                    <textarea
                      className="ws-textarea"
                      value={form.argumentsText}
                      onChange={(event) =>
                        updateForm({ argumentsText: event.target.value })
                      }
                      spellCheck={false}
                    />
                  </label>
                  <label className="ws-field">
                    <span className="ws-label">Context</span>
                    <textarea
                      className="ws-textarea"
                      value={form.context}
                      onChange={(event) => updateForm({ context: event.target.value })}
                      spellCheck={false}
                    />
                    <span className="ws-hint">
                      This is the content the detectors scan. The response shows the
                      exact request that was evaluated.
                    </span>
                  </label>

                  {formError ? (
                    <Banner tone="error" icon={AlertTriangle}>
                      {formError}
                    </Banner>
                  ) : null}

                  <p className="ws-hint">
                    The harness executes the saved server-side scenario. Edits above
                    are a local preview and are not sent to the gateway.
                  </p>
                  <div className="ws-between">
                    <button
                      type="button"
                      className="ws-btn is-sm is-ghost"
                      onClick={resetForm}
                      disabled={!dirty || running}
                    >
                      <RotateCcw className="h-3.5 w-3.5" /> Reset payload
                    </button>
                    <button
                      type="submit"
                      className="ws-btn is-primary is-sm"
                      disabled={running || !selected}
                    >
                      {running ? (
                        <InlineLoading label="Running both sides" />
                      ) : (
                        <>
                          <Play className="h-3.5 w-3.5" /> Run isolated test
                        </>
                      )}
                    </button>
                  </div>
                </form>
              ) : (
                <EmptyState
                  title="Select a scenario."
                  description="Choose an attack to inspect and edit its exact payload."
                  icon={Swords}
                />
              )}
            </CardBody>
          </Card>
        </div>
      </div>

      <Card>
        <CardHead
          title="Enforcement comparison"
          subtitle="Two real runs · ON blocks at the boundary, OFF records the would-be verdict"
          icon={GitCompare}
          actions={
            result ? (
              <CopyButton value={JSON.stringify(result, null, 2)} label="Copy result" />
            ) : null
          }
        />
        <CardBody>
          {result ? (
            <div className="ws-stack">
              <div className="ws-wrap">
                <StatusBadge tone={result.comparison.verdict_changed ? "warn" : "ok"}>
                  verdict {result.comparison.verdict_changed ? "changed" : "unchanged"}
                </StatusBadge>
                <StatusBadge tone={result.comparison.gate_off_permitted ? "warn" : "neutral"}>
                  OFF permitted: {result.comparison.gate_off_permitted ? "yes" : "no"}
                </StatusBadge>
                <StatusBadge tone={result.comparison.gate_on_blocked ? "ok" : "neutral"}>
                  ON blocked: {result.comparison.gate_on_blocked ? "yes" : "no"}
                </StatusBadge>
                <span className="ws-badge is-neutral">
                  run {result.run_id}
                </span>
              </div>

              <div className="ws-comparison">
                <RunSide
                  label="Enforcement ON"
                  tone="on"
                  side={result.on}
                />
                <RunSide
                  label="Enforcement OFF"
                  tone="off"
                  side={result.off}
                />
              </div>

              <div className="ws-grid ws-grid-2">
                <Card flat>
                  <CardHead
                    title="Exact request evaluated"
                    subtitle="Server-side harness input"
                    icon={Terminal}
                  />
                  <CardBody>
                    <KeyValue
                      items={[
                        { label: "Tool", value: result.request.tool_name, mono: true },
                        {
                          label: "Source",
                          value: <SourceBadge source={result.request.source} />,
                        },
                        {
                          label: "Scenario",
                          value: result.scenario_id ?? "manual payload",
                          mono: true,
                        },
                        {
                          label: "Harness",
                          value: String(result.request.metadata.harness ?? "—"),
                        },
                        {
                          label: "Session",
                          value: String(result.request.metadata.session_id ?? "—"),
                          mono: true,
                        },
                      ]}
                    />
                    <JsonBlock
                      className="mt-3"
                      value={result.request.arguments}
                      title="Arguments"
                      collapsedLines={8}
                    />
                    {result.request.context ? (
                      <JsonBlock
                        className="mt-3"
                        value={result.request.context}
                        title="Context"
                        collapsedLines={8}
                      />
                    ) : null}
                  </CardBody>
                </Card>

                <Card flat>
                  <CardHead
                    title="Isolation & notes"
                    subtitle="No global switch mutation"
                    icon={ShieldCheck}
                  />
                  <CardBody>
                    <div className="ws-stack">
                      <KeyValue
                        items={[
                          {
                            label: "Global switch",
                            value: result.global_enforcement_unchanged
                              ? "unchanged"
                              : "NOT CONFIRMED",
                          },
                          {
                            label: "Audit path",
                            value: result.audit_path,
                            mono: true,
                          },
                          {
                            label: "Generated",
                            value: formatTimestamp(result.generated_at),
                          },
                        ]}
                      />
                      {Object.entries(result.notes).map(([key, note]) => (
                        <div className="ws-rule-note" key={key}>
                          <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                          <span>{note}</span>
                        </div>
                      ))}
                    </div>
                  </CardBody>
                </Card>
              </div>
            </div>
          ) : (
            <EmptyState
              title="No run in this session."
              description="Choose a scenario, inspect the payload and run it. Both ON and OFF results will appear here with real decisions, durations and audit call IDs."
              icon={GitCompare}
            />
          )}
        </CardBody>
      </Card>

      <div className="ws-grid ws-grid-sidebar">
        <Card>
          <CardHead
            title="Red-team history"
            subtitle="Dedicated red-team audit file · newest first"
            icon={History}
            actions={
              <span className="ws-count-pill">
                {history.data?.available ? `${historyEntries.length} runs` : "file unavailable"}
              </span>
            }
          />
          <CardBody flush>
            {history.isLoading ? (
              <div className="p-4">
                <LoadingState rows={2} />
              </div>
            ) : history.failure && !history.data ? (
              <div className="p-4">
                <ErrorState failure={history.failure} onRetry={() => void history.refresh()} />
              </div>
            ) : historyEntries.length ? (
              <div className="ws-table-wrap">
                <table className="ws-table">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Decision</th>
                      <th>Tool</th>
                      <th>Source</th>
                      <th>Scenario / session</th>
                      <th>Call ID</th>
                    </tr>
                  </thead>
                  <tbody>
                    {historyEntries.map((entry) => {
                      const scenario = String(entry.metadata?.scenario_id ?? "—");
                      return (
                        <tr
                          key={entry.call_id}
                          className={cn(
                            "is-clickable",
                            historyCall === entry.call_id && "is-selected",
                          )}
                          onClick={() => setHistoryCall(entry.call_id)}
                          tabIndex={0}
                          onKeyDown={(event) => {
                            if (event.key === "Enter" || event.key === " ") {
                              event.preventDefault();
                              setHistoryCall(entry.call_id);
                            }
                          }}
                        >
                          <td className="is-nowrap text-[10.5px] text-[#6f6c66]">
                            {formatTimestamp(entry.ts)}
                          </td>
                          <td>
                            <DecisionBadge decision={entry.decision} short />
                          </td>
                          <td className="font-mono text-[10.5px]">{entry.tool}</td>
                          <td>
                            <SourceBadge source={entry.source} />
                          </td>
                          <td className="font-mono text-[9.5px]">{scenario}</td>
                          <td className="font-mono text-[9.5px]">{entry.call_id}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            ) : (
              <EmptyState
                title="No red-team runs recorded."
                description="Run a scenario to write the first isolated audit entry. This file is separate from the main gateway audit trail."
                icon={History}
              />
            )}
          </CardBody>
        </Card>

        <div className="ws-detail">
          <Card>
            <CardHead
              title="History record"
              subtitle="Full audit entry from the red-team file"
              icon={Terminal}
              actions={
                selectedHistory ? (
                  <CopyButton
                    value={JSON.stringify(selectedHistory, null, 2)}
                    label="Copy JSON"
                  />
                ) : null
              }
            />
            <CardBody>
              {selectedHistory ? (
                <HistoryDetail entry={selectedHistory} />
              ) : (
                <EmptyState
                  title="Select a history row."
                  description="Inspect the full audit entry written by an isolated red-team run."
                  icon={History}
                />
              )}
            </CardBody>
          </Card>
        </div>
      </div>
    </div>
  );
}

function RunSide({
  label,
  tone,
  side,
}: {
  label: string;
  tone: "on" | "off";
  side: RedteamRunResponse["on"];
}) {
  return (
    <div className={cn("ws-comparison-side", `is-${tone}`)}>
      <div className="ws-between">
        <span className="ws-label">{label}</span>
        <DecisionBadge decision={side.decision} />
      </div>
      <p className="mt-2 text-[12px] font-semibold leading-snug">{side.headline}</p>
      <div className="ws-wrap mt-2">
        <StatusBadge tone={side.fail_closed ? "warn" : "neutral"}>
          fail closed: {side.fail_closed ? "yes" : "no"}
        </StatusBadge>
        <span className="ws-badge is-neutral">
          <Clock3 className="h-3 w-3" /> {formatDurationMs(side.duration_ms)}
        </span>
      </div>
      <div className="ws-copy-row mt-3">
        <span className="ws-label">Call ID</span>
        <CopyButton value={side.call_id} label="Copy" />
      </div>
      <div className="font-mono text-[9.5px] text-[#4d4a45]">{side.call_id}</div>
      <div className="mt-3">
        <span className="ws-label">Stages</span>
        <StageList stages={side.stages} />
      </div>
      <div className="mt-3">
        <span className="ws-label">Policy reasons</span>
        <ReasonList reasons={side.reasons} />
      </div>
      <div className="mt-3">
        <span className="ws-label">Detector output</span>
        <DetectionList detections={side.detections} compact />
      </div>
    </div>
  );
}

function HistoryDetail({ entry }: { entry: AuditEntry }) {
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
          { label: "Scenario", value: String(entry.metadata?.scenario_id ?? "—") },
          { label: "Session", value: String(entry.metadata?.session_id ?? "—"), mono: true },
          { label: "Fail closed", value: entry.fail_closed ? "yes" : "no" },
        ]}
      />
      <div>
        <span className="ws-label">Policy reasons</span>
        <ReasonList reasons={entry.reasons ?? []} />
      </div>
      <JsonBlock value={entry.arguments ?? {}} title="Arguments" collapsedLines={8} />
      <JsonBlock value={entry} title="Full audit record" collapsedLines={12} />
    </div>
  );
}
