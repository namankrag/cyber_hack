"use client";

import { CheckCircle2, FlaskConical, RefreshCcw, XCircle } from "lucide-react";
import Link from "next/link";
import { useMemo, useState } from "react";
import { formatNumber } from "@/lib/api/format";
import type {
  BenchLatestResponse,
  BenchRun,
  ScorecardGate,
  ScorecardResponse,
} from "@/lib/api/types";
import { useLiveData } from "@/lib/hooks/use-live-data";
import { cn } from "@/lib/utils";
import {
  Card,
  CardBody,
  CardHead,
  DecisionBadge,
  EmptyState,
  ErrorState,
  LoadingState,
} from "@/components/workspace/ui";

function pct(value: number, digits = 1): string {
  return `${(value * 100).toFixed(digits)}%`;
}

/** "20261030T194436Z" -> Date (UTC). Returns null for anything else. */
export function parseCompactUtc(value: string): Date | null {
  const m = /^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z$/.exec(value);
  if (!m) return null;
  const [, y, mo, d, h, mi, s] = m.map(Number);
  return new Date(Date.UTC(y, mo - 1, d, h, mi, s));
}

function runDate(value: string | null | undefined): string {
  if (!value) return "—";
  const date = parseCompactUtc(value) ?? new Date(value);
  return Number.isNaN(date.getTime())
    ? value
    : date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

function humanize(id: string): string {
  const text = id.replace(/_/g, " ");
  return text.charAt(0).toUpperCase() + text.slice(1);
}

/* ------------------------------------------------------------------ bench */

function BenchHeadline({ run }: { run: BenchRun }) {
  const s = run.summary;
  const bars = [
    { label: "Enforcement OFF", value: s.attack_success_off, tone: "is-off" },
    { label: "Enforcement ON", value: s.attack_success_on, tone: "is-on" },
  ];
  return (
    <div className="ws-proof-bench">
      <p className="ws-label">Attacks that succeeded ({formatNumber(s.n_malicious)} malicious cases)</p>
      <ul className="ws-proof-hbars">
        {bars.map((bar) => (
          <li key={bar.label}>
            <span className="ws-proof-hbar-label">{bar.label}</span>
            <span className="ws-proof-hbar-track">
              <span
                className={cn("ws-proof-hbar-fill", bar.tone)}
                style={{ width: `${Math.max(bar.value * 100, 0.6)}%` }}
              />
            </span>
            <strong>{pct(bar.value)}</strong>
          </li>
        ))}
      </ul>
      <div className="ws-proof-chips">
        <span>
          <strong>{pct(s.false_positive_rate_benign)}</strong> benign calls wrongly denied
        </span>
        <span>
          <strong>{pct(s.approval_correctness, 0)}</strong> high-impact calls held correctly
        </span>
        <span>
          <strong>{s.latency_ms_on.p50.toFixed(2)} ms</strong> p50 decision time
        </span>
      </div>
      <p className="ws-hint">
        {formatNumber(run.n_cases)} synthetic cases ({formatNumber(s.n_malicious)} malicious ·{" "}
        {formatNumber(s.n_benign)} benign · {formatNumber(s.n_approval)} approval) · detectors:{" "}
        {run.config.detectors.join(", ")} · run {runDate(run.generated_at_utc)}
      </p>
    </div>
  );
}

function BenchOutcomeSplit({ run }: { run: BenchRun }) {
  const s = run.summary;
  const parts = [
    { label: "Denied", value: s.attack_denied_on, tone: "is-deny" },
    { label: "Held for a human", value: s.attack_held_on, tone: "is-hold" },
    { label: "Got through", value: s.attack_success_on, tone: "is-through" },
  ];
  return (
    <div className="ws-proof-split">
      <p className="ws-label">What happened to attacks with enforcement ON</p>
      <div className="ws-proof-split-bar" role="img" aria-label={parts.map((p) => `${p.label} ${pct(p.value)}`).join(", ")}>
        {parts.map((part) =>
          part.value > 0 ? (
            <span key={part.label} className={part.tone} style={{ flexGrow: part.value }} />
          ) : null,
        )}
      </div>
      <ul className="ws-vchart-legend">
        {parts.map((part) => (
          <li key={part.label}>
            <span className={cn("ws-proof-swatch", part.tone)} aria-hidden="true" />
            {part.label} <strong>{pct(part.value)}</strong>
          </li>
        ))}
      </ul>
    </div>
  );
}

function BenchCases({ run }: { run: BenchRun }) {
  const [type, setType] = useState("all");
  const [mismatchOnly, setMismatchOnly] = useState(false);
  const types = useMemo(
    () => Array.from(new Set(run.cases.map((c) => c.attack_type))).sort(),
    [run.cases],
  );
  const rows = run.cases.filter(
    (c) => (type === "all" || c.attack_type === type) && (!mismatchOnly || !c.match_on),
  );
  return (
    <div className="ws-proof-cases">
      <div className="ws-proof-filters">
        <label>
          Attack type{" "}
          <select value={type} onChange={(event) => setType(event.target.value)}>
            <option value="all">All ({run.cases.length})</option>
            {types.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
        </label>
        <label>
          <input
            type="checkbox"
            checked={mismatchOnly}
            onChange={(event) => setMismatchOnly(event.target.checked)}
          />{" "}
          Only cases where ON differs from expected
        </label>
        <span className="ws-hint">{rows.length} shown</span>
      </div>
      <div className="ws-table-wrap">
        <table className="ws-table">
          <thead>
            <tr>
              <th>Case</th>
              <th>Attack type</th>
              <th>Tool</th>
              <th>Source</th>
              <th>Expected</th>
              <th>OFF</th>
              <th>ON</th>
              <th>Match</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((c) => (
              <tr key={c.id}>
                <td className="font-mono ws-fs-meta" title={c.label}>
                  {c.id}
                </td>
                <td className="ws-fs-meta">{c.attack_type}</td>
                <td className="font-mono ws-fs-meta">{c.tool}</td>
                <td className="ws-fs-meta">{c.source}</td>
                <td>
                  <DecisionBadge decision={c.expected} short />
                </td>
                <td>
                  <DecisionBadge decision={c.actual_off} short />
                </td>
                <td>
                  <DecisionBadge decision={c.actual_on} short />
                </td>
                <td>{c.match_on ? "✓" : <span className="ws-proof-miss">miss</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export function BenchmarkPanel({ compact = false }: { compact?: boolean }) {
  const bench = useLiveData<BenchLatestResponse>("/v1/bench/latest", { intervalMs: 300_000 });
  const run = bench.data?.latest ?? null;
  return (
    <Card>
      <CardHead
        title="Benchmark: with vs without AgentShield"
        subtitle="The same frozen attack and benign cases, run with enforcement OFF and ON"
        icon={FlaskConical}
        actions={
          compact ? (
            <Link href="/workspace/evidence#benchmark" className="ws-link">
              All cases
            </Link>
          ) : null
        }
      />
      <CardBody>
        {bench.isLoading ? (
          <LoadingState rows={1} />
        ) : bench.failure && !bench.data ? (
          <ErrorState failure={bench.failure} onRetry={() => void bench.refresh()} compact />
        ) : !run ? (
          <EmptyState
            icon={FlaskConical}
            title="No benchmark run recorded"
            description="Run python scripts/benchmark.py to produce bench/results_*.json."
          />
        ) : (
          <div className="ws-stack">
            <BenchHeadline run={run} />
            {compact ? null : (
              <>
                <BenchOutcomeSplit run={run} />
                <BenchCases run={run} />
              </>
            )}
          </div>
        )}
      </CardBody>
    </Card>
  );
}

/* -------------------------------------------------------------- scorecard */

function GateList({ gates }: { gates: Record<string, ScorecardGate> }) {
  return (
    <ul className="ws-proof-gates">
      {Object.entries(gates).map(([id, gate]) => (
        <li key={id} className={gate.passed ? "is-ok" : "is-fail"}>
          {gate.passed ? <CheckCircle2 className="h-4 w-4" /> : <XCircle className="h-4 w-4" />}
          <span className="ws-proof-gate-name">{humanize(id)}</span>
          <span className="ws-proof-gate-actual">{String(gate.actual ?? "—")}</span>
          <span className="ws-proof-gate-target">target {String(gate.target ?? "—")}</span>
        </li>
      ))}
    </ul>
  );
}

/** Single-series columns (one hue, so no legend box: the label names it). */
function LoopColumns({
  points,
}: {
  points: Array<{ label: string; value: number; note: string }>;
}) {
  const top = Math.max(1, ...points.map((p) => p.value));
  const ticks = Array.from(new Set([0, Math.ceil(top / 2), top]));
  return (
    <figure className="ws-vchart">
      <div className="ws-vchart-body">
        <div className="ws-vchart-yaxis is-short" aria-hidden="true">
          {ticks.map((tick) => (
            <span key={tick} style={{ bottom: `${(tick / top) * 100}%` }}>
              {tick}
            </span>
          ))}
        </div>
        <div className="ws-vchart-plot is-short">
          {ticks.map((tick) => (
            <i key={tick} className="ws-vchart-grid" style={{ bottom: `${(tick / top) * 100}%` }} aria-hidden="true" />
          ))}
          <ol className="ws-vchart-cols" aria-label="Confirmed vulnerabilities per loop iteration">
            {points.map((point, index) => (
              <li
                key={point.label}
                className={cn(
                  "ws-vchart-col",
                  point.value === 0 && "is-empty",
                  index === 0 ? "is-first" : index === points.length - 1 ? "is-last" : undefined,
                )}
                tabIndex={point.value > 0 ? 0 : -1}
                aria-label={`${point.label}: ${point.value} confirmed. ${point.note}`}
              >
                {point.value > 0 ? (
                  <span className="ws-vchart-bar" style={{ height: `${(point.value / top) * 100}%` }}>
                    <span className="ws-vchart-seg is-deny is-top" style={{ flexGrow: 1 }} />
                    <span className="ws-vchart-cap">{point.value}</span>
                    <span className="ws-vchart-tip" aria-hidden="true">
                      <strong>{point.label}</strong>
                      <span className="ws-vchart-tip-total">{point.value} confirmed</span>
                      <span>{point.note}</span>
                    </span>
                  </span>
                ) : (
                  <span className="ws-proof-zero">0</span>
                )}
              </li>
            ))}
          </ol>
        </div>
      </div>
      <div className="ws-vchart-xaxis" aria-hidden="true">
        {points.map((point) => (
          <span key={point.label}>{point.label}</span>
        ))}
      </div>
    </figure>
  );
}

export function ScorecardPanel({ compact = false }: { compact?: boolean }) {
  const card = useLiveData<ScorecardResponse>("/v1/evidence/scorecard", { intervalMs: 300_000 });
  const data = card.data;
  return (
    <Card>
      <CardHead
        title="Closed loop: block → fix the code → re-attack"
        subtitle="Runtime blocks drive code fixes; the loop repeats until nothing exploitable remains"
        icon={RefreshCcw}
        actions={
          compact ? (
            <Link href="/workspace/evidence#closed-loop" className="ws-link">
              Details
            </Link>
          ) : null
        }
      />
      <CardBody>
        {card.isLoading ? (
          <LoadingState rows={1} />
        ) : card.failure && !data ? (
          <ErrorState failure={card.failure} onRetry={() => void card.refresh()} compact />
        ) : !data || !data.available ? (
          <EmptyState
            icon={RefreshCcw}
            title="No scorecard on this gateway"
            description={data && !data.available ? data.reason : "The scorecard could not be loaded."}
          />
        ) : (
          <ScorecardBody data={data} compact={compact} />
        )}
      </CardBody>
    </Card>
  );
}

function ScorecardBody({
  data,
  compact,
}: {
  data: Extract<ScorecardResponse, { available: true }>;
  compact: boolean;
}) {
  const gates = Object.values(data.gates);
  const passedCount = gates.filter((g) => g.passed).length;
  const iterations = data.loop.iterations;
  const points = iterations.map((it) => ({
    label: `#${it.iteration}`,
    value: it.confirmed_before ?? 0,
    note: `${it.deployed_exploit_blocked ? "exploit blocked after patch" : "exploit not blocked"} · ${
      it.regression_passed ? "regression green" : "regression failed"
    }`,
  }));
  const last = iterations[iterations.length - 1];
  if (last && last.confirmed_after != null) {
    points.push({ label: "after", value: last.confirmed_after, note: "residual after the final iteration" });
  }
  const funnel = data.code_funnel as Record<string, number | undefined>;
  return (
    <div className="ws-stack">
      <div className="ws-proof-headline">
        <span className={cn("ws-badge", data.passed ? "is-allow" : "is-deny")}>
          {passedCount}/{gates.length} gates passed
        </span>
        <span>
          Loop {data.loop.converged ? "converged" : String(data.loop.status ?? "did not converge")} in{" "}
          <strong>{formatNumber(data.loop.iterations_to_converge ?? iterations.length)}</strong> iterations ·{" "}
          <strong>{formatNumber(data.loop.residual_confirmed ?? 0)}</strong> exploitable vulnerabilities left
        </span>
      </div>
      <div className={cn("ws-proof-scorecard", compact && "is-compact")}>
        <div>
          <p className="ws-label">Confirmed vulnerabilities, iteration by iteration</p>
          <LoopColumns points={points} />
        </div>
        {compact ? null : (
          <div>
            <p className="ws-label">Acceptance gates</p>
            <GateList gates={data.gates} />
          </div>
        )}
      </div>
      {compact ? null : (
        <>
          <div className="ws-proof-chips">
            <span>
              <strong>{formatNumber(funnel.raw_alerts)}</strong> scanner alerts
            </span>
            <span>
              <strong>{formatNumber(funnel.confirmed)}</strong> proven by exploit
            </span>
            <span>
              <strong>{formatNumber(funnel.fixed)}</strong> fixed &amp; verified
            </span>
            <span>
              <strong>
                {formatNumber(funnel.variants_blocked)}/{formatNumber(funnel.variants_total)}
              </strong>{" "}
              payload variants blocked
            </span>
            <span>
              precision <strong>{pct(Number(funnel.precision_before ?? 0), 0)}</strong> →{" "}
              <strong>{pct(Number(funnel.precision_after ?? 0), 0)}</strong>
            </span>
          </div>
          <div className="ws-table-wrap">
            <table className="ws-table">
              <thead>
                <tr>
                  <th>Runtime scenario</th>
                  <th>Attack type</th>
                  <th>Tool</th>
                  <th>Expected</th>
                  <th>Actual</th>
                  <th>Result</th>
                </tr>
              </thead>
              <tbody>
                {data.runtime_scenarios.map((row) => (
                  <tr key={row.id}>
                    <td className="ws-fs-meta">{row.label}</td>
                    <td className="ws-fs-meta">{row.attack_type}</td>
                    <td className="font-mono ws-fs-meta">{row.tool}</td>
                    <td>
                      <DecisionBadge decision={row.expected_decision} short />
                    </td>
                    <td>
                      <DecisionBadge decision={row.actual_decision} short />
                    </td>
                    <td>{row.passed ? "✓ pass" : <span className="ws-proof-miss">fail</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="ws-hint">
            Source: {data.path} · generated {data.generated_at ? new Date(data.generated_at).toLocaleString() : "—"}
          </p>
        </>
      )}
    </div>
  );
}
