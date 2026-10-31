import type { ComponentType, ReactNode } from "react";
import Link from "next/link";
import {
  AlertTriangle,
  CheckCircle2,
  ChevronRight,
  CircleAlert,
  Inbox,
  Loader2,
  ShieldAlert,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import {
  decisionClass,
  decisionLabel,
  decisionShortLabel,
  formatClock,
  formatNumber,
  sourceClass,
  sourceLabel,
} from "@/lib/api/format";
import type {
  DetectionResult,
  PolicyReason,
  RedteamStage,
} from "@/lib/api/types";
import { cn } from "@/lib/utils";
import { failureHint, failureTitle, type ApiFailure } from "@/lib/api/errors";

export function PageHeader({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow: string;
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <header className="ws-page-head">
      <div className="ws-page-head-copy">
        <p className="ws-eyebrow">{eyebrow}</p>
        <h1 className="ws-page-title">{title}</h1>
        {description ? <p className="ws-page-sub">{description}</p> : null}
      </div>
      {actions ? <div className="ws-page-actions">{actions}</div> : null}
    </header>
  );
}

export function Card({
  children,
  className,
  flat = false,
  id,
}: {
  children: ReactNode;
  className?: string;
  flat?: boolean;
  id?: string;
}) {
  return (
    <section id={id} className={cn("ws-card", flat && "is-flat", className)}>
      {children}
    </section>
  );
}

export function CardHead({
  title,
  subtitle,
  icon: Icon,
  actions,
  tight = false,
}: {
  title: ReactNode;
  subtitle?: ReactNode;
  icon?: LucideIcon;
  actions?: ReactNode;
  tight?: boolean;
}) {
  return (
    <div className={cn("ws-card-head", tight && "is-tight")}>
      <div className="min-w-0">
        <div className="ws-card-title">
          {Icon ? <Icon className="h-3.5 w-3.5" strokeWidth={1.8} /> : null}
          <span className="ws-truncate">{title}</span>
        </div>
        {subtitle ? <p className="ws-card-sub">{subtitle}</p> : null}
      </div>
      {actions ? <div className="ws-row shrink-0">{actions}</div> : null}
    </div>
  );
}

export function CardBody({
  children,
  className,
  tight = false,
  flush = false,
}: {
  children: ReactNode;
  className?: string;
  tight?: boolean;
  flush?: boolean;
}) {
  return (
    <div
      className={cn(
        "ws-card-body",
        tight && "is-tight",
        flush && "is-flush",
        className,
      )}
    >
      {children}
    </div>
  );
}

export function CardFoot({ children }: { children: ReactNode }) {
  return <div className="ws-card-foot">{children}</div>;
}

export function DecisionBadge({
  decision,
  short = false,
  className,
}: {
  decision: string;
  short?: boolean;
  className?: string;
}) {
  return (
    <span className={cn("ws-badge", decisionClass(decision), className)}>
      {short ? decisionShortLabel(decision) : decisionLabel(decision)}
    </span>
  );
}

export function SourceBadge({ source }: { source: string }) {
  return (
    <span className={cn("ws-badge", sourceClass(source))}>
      {sourceLabel(source)}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: string }) {
  const cls =
    severity === "critical" || severity === "high"
      ? "is-deny"
      : severity === "medium"
        ? "is-hold"
        : "is-allow";
  return <span className={cn("ws-badge", cls)}>{severity}</span>;
}

export function StatusBadge({
  tone,
  children,
}: {
  tone: "ok" | "warn" | "error" | "neutral" | "dark" | "purple" | "lime";
  children: ReactNode;
}) {
  const cls =
    tone === "ok"
      ? "is-allow"
      : tone === "warn"
        ? "is-warn"
        : tone === "error"
          ? "is-error"
          : tone === "dark"
            ? "is-dark"
            : tone === "purple"
              ? "is-purple"
              : tone === "lime"
                ? "is-lime"
                : "is-neutral";
  return <span className={cn("ws-badge", cls)}>{children}</span>;
}

export function Dot({ tone = "neutral" }: { tone?: "ok" | "warn" | "error" | "live" | "neutral" }) {
  return <span className={cn("ws-dot", `is-${tone}`)} aria-hidden="true" />;
}

export function SkeletonPill({ label = "Loading" }: { label?: string }) {
  return (
    <span className="ws-skeleton-pill" role="status" aria-label={label} />
  );
}

export function ValueSkeleton({ label = "Loading value" }: { label?: string }) {
  return (
    <span className="ws-skeleton ws-value-skel" role="status" aria-label={label} />
  );
}

export function StatCard({
  label,
  value,
  meta,
  icon: Icon,
  tone,
  badge,
  visual,
  loading = false,
}: {
  label: string;
  value: ReactNode;
  meta?: ReactNode;
  icon?: LucideIcon;
  tone?: "purple" | "lime" | "navy" | "peach" | "cream" | "blue";
  badge?: ReactNode;
  visual?: ReactNode;
  loading?: boolean;
}) {
  if (loading) {
    return (
      <div className={cn("ws-stat", tone && `is-${tone}`)} aria-busy="true" aria-label={`${typeof label === "string" ? label : "Statistic"} loading`}>
        <div className="ws-stat-top">
          <span className="ws-stat-label">{label}</span>
          {Icon ? (
            <span className="ws-stat-icon" aria-hidden="true">
              <Icon className="h-4 w-4" strokeWidth={1.7} />
            </span>
          ) : null}
        </div>
        <div className="ws-stat-main">
          <div className="ws-stat-value" aria-hidden="true">
            <span className="ws-skeleton ws-stat-value-skel" />
          </div>
        </div>
        <div className="ws-stat-meta" aria-hidden="true">
          <span className="ws-skeleton ws-meta-skel" />
        </div>
      </div>
    );
  }
  return (
    <div className={cn("ws-stat", tone && `is-${tone}`)}>
      <div className="ws-stat-top">
        <span className="ws-stat-label">{label}</span>
        {badge ?? (Icon ? (
          <span className="ws-stat-icon">
            <Icon className="h-4 w-4" strokeWidth={1.7} />
          </span>
        ) : null)}
      </div>
      <div className="ws-stat-main">
        <div className="ws-stat-value">{value}</div>
        {visual ? <div className="ws-stat-visual">{visual}</div> : null}
      </div>
      {meta ? <div className="ws-stat-meta">{meta}</div> : null}
    </div>
  );
}

export function PastelMetricCard(props: Parameters<typeof StatCard>[0]) {
  return <StatCard {...props} />;
}

export function KeyValue({
  items,
}: {
  items: Array<{ label: ReactNode; value: ReactNode; mono?: boolean }>;
}) {
  return (
    <dl className="ws-kv">
      {items.map((item, index) => (
        <div key={index} className="contents">
          <dt>{item.label}</dt>
          <dd className={item.mono ? "is-mono" : undefined}>{item.value}</dd>
        </div>
      ))}
    </dl>
  );
}

export function ReasonList({
  reasons,
  empty = "No policy reasons were recorded.",
}: {
  reasons: PolicyReason[];
  empty?: string;
}) {
  if (!reasons.length) {
    return <p className="ws-hint">{empty}</p>;
  }
  return (
    <ol className="ws-reasons">
      {reasons.map((reason, index) => (
        <li key={`${reason.rule}-${index}`} className="ws-reason">
          <span className="ws-reason-index">{String(index + 1).padStart(2, "0")}</span>
          <div className="ws-reason-copy">
            <div className="ws-reason-rule">
              <span>{reason.rule}</span>
              <DecisionBadge decision={reason.decision} short />
            </div>
            <p className="ws-reason-detail">{reason.detail}</p>
          </div>
        </li>
      ))}
    </ol>
  );
}

export function DetectionList({
  detections,
  compact = false,
}: {
  detections: DetectionResult[];
  compact?: boolean;
}) {
  if (!detections.length) {
    return <p className="ws-hint">No detector output recorded.</p>;
  }
  return (
    <div className="ws-stack-sm">
      {detections.map((detection, index) => (
        <div
          key={`${detection.detector}-${index}`}
          className={cn(
            "ws-detection",
            detection.error
              ? "is-warn"
              : detection.is_threat
                ? "is-threat"
                : "is-clean",
          )}
        >
          <div className="ws-between">
            <span className="ws-mono ws-fs-body font-semibold">
              {detection.detector}
            </span>
            <div className="ws-row">
              {detection.error ? (
                <StatusBadge tone="warn">error</StatusBadge>
              ) : detection.is_threat ? (
                <StatusBadge tone="error">threat</StatusBadge>
              ) : (
                <StatusBadge tone="ok">clean</StatusBadge>
              )}
              <span className="ws-mono ws-fs-meta ws-ink-soft">
                {detection.score.toFixed(2)}
              </span>
            </div>
          </div>
          {detection.error ? (
            <p className="ws-detection-error">
              {detection.error}
            </p>
          ) : null}
          {!compact && detection.signals.length ? (
            <div className="ws-signal-list">
              {detection.signals.map((signal) => (
                <span className="ws-signal" key={signal}>
                  {signal}
                </span>
              ))}
            </div>
          ) : null}
        </div>
      ))}
    </div>
  );
}

export function StageList({ stages }: { stages: RedteamStage[] }) {
  return (
    <div className="ws-stages">
      {stages.map((stage, index) => (
        <div
          key={stage.key}
          className={cn(
            "ws-stage",
            stage.status === "warning" && "is-warning",
            stage.blocked && "is-blocked",
          )}
        >
          <span className="ws-stage-index">{String(index + 1).padStart(2, "0")}</span>
          <div className="ws-stage-copy">
            <strong>{stage.label}</strong>
            <span>{stage.detail}</span>
          </div>
        </div>
      ))}
    </div>
  );
}

export function Distribution({
  allow,
  hold,
  deny,
  labels = true,
  percentages = false,
}: {
  allow: number;
  hold: number;
  deny: number;
  labels?: boolean;
  percentages?: boolean;
}) {
  const total = allow + hold + deny;
  if (total <= 0) {
    return (
      <>
        <div className="ws-dist is-empty" role="img" aria-label="No activity in this window">
          <span />
        </div>
        <p className="ws-hint">No activity in this window.</p>
      </>
    );
  }
  const percent = (value: number) => `${((value / total) * 100).toFixed(1)}%`;
  return (
    <>
      <div
        className="ws-dist"
        role="img"
        aria-label={`${allow} allowed, ${hold} held for approval, ${deny} denied`}
      >
        {allow > 0 ? <span className="is-allow" style={{ width: `${(allow / total) * 100}%` }} /> : null}
        {hold > 0 ? <span className="is-hold" style={{ width: `${(hold / total) * 100}%` }} /> : null}
        {deny > 0 ? <span className="is-deny" style={{ width: `${(deny / total) * 100}%` }} /> : null}
      </div>
      {labels ? (
        <div className="ws-legend">
          <span className="ws-legend-item">
            <span className="ws-legend-swatch is-allow" /> Allow {formatNumber(allow)}
            {percentages ? ` · ${percent(allow)}` : null}
          </span>
          <span className="ws-legend-item">
            <span className="ws-legend-swatch is-hold" /> Approval {formatNumber(hold)}
            {percentages ? ` · ${percent(hold)}` : null}
          </span>
          <span className="ws-legend-item">
            <span className="ws-legend-swatch is-deny" /> Deny {formatNumber(deny)}
            {percentages ? ` · ${percent(deny)}` : null}
          </span>
        </div>
      ) : null}
    </>
  );
}

export function Bars({
  rows,
  empty = "No activity in this window.",
}: {
  rows: Array<{
    label: string;
    value: number;
    note?: string;
    tone?: "allow" | "hold" | "deny";
    segments?: Array<{ value: number; tone: "allow" | "hold" | "deny" }>;
  }>;
  empty?: string;
}) {
  if (!rows.length) return <p className="ws-hint">{empty}</p>;
  const max = Math.max(...rows.map((row) => row.value), 1);
  return (
    <div className="ws-bars">
      {rows.map((row) => (
        <div className="ws-bar-row" key={row.label}>
          <span className="ws-truncate" title={row.label}>
            {row.label}
          </span>
          {row.segments?.length ? (
            <span
              className="ws-bar-track is-stacked"
              role="img"
              aria-label={`${row.label}: ${row.segments.map((segment) => `${segment.value} ${segment.tone}`).join(", ")}`}
            >
              {row.segments.map((segment, index) =>
                segment.value > 0 ? (
                  <span
                    key={index}
                    className={cn("ws-bar-seg", `is-${segment.tone}`)}
                    style={{ width: `${(segment.value / Math.max(row.value, 1)) * 100}%` }}
                  />
                ) : null,
              )}
            </span>
          ) : (
            <span className="ws-bar-track" aria-hidden="true">
              <span
                className={cn("ws-bar-fill", row.tone && `is-${row.tone}`)}
                style={{ width: `${row.value > 0 ? (row.value / max) * 100 : 0}%` }}
              />
            </span>
          )}
          <span className="ws-mono ws-fs-label ws-ink-soft">
            {row.note ?? formatNumber(row.value)}
          </span>
        </div>
      ))}
    </div>
  );
}

type TrendPoint = {
  ts: number;
  total: number;
  allow: number;
  deny: number;
  require_approval: number;
  threats: number;
};

/** Smallest 1/2/5 x 10^n step that splits `max` into at most four intervals. */
function niceScale(max: number): { top: number; ticks: number[] } {
  const raw = Math.max(max, 1) / 4;
  const magnitude = 10 ** Math.floor(Math.log10(raw));
  const step = Math.max(1, [1, 2, 5, 10].map((m) => m * magnitude).find((v) => v >= raw) ?? 1);
  const top = Math.max(step, Math.ceil(max / step) * step);
  const ticks: number[] = [];
  for (let value = 0; value <= top; value += step) ticks.push(value);
  return { top, ticks };
}

function bucketLabel(ts: number, spanSeconds: number): string {
  const date = new Date(ts * 1000);
  if (spanSeconds >= 86_400) {
    return date.toLocaleDateString(undefined, { month: "short", day: "numeric" });
  }
  return date.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", hour12: false });
}

/** The series drawn last (visually on top) gets the rounded data-end. */
function topKey(point: TrendPoint): string | undefined {
  return [...TREND_SERIES].reverse().find((item) => point[item.key] > 0)?.key;
}

const TREND_SERIES = [
  { key: "allow", label: "Allow", tone: "is-allow" },
  { key: "require_approval", label: "Approval", tone: "is-hold" },
  { key: "deny", label: "Deny", tone: "is-deny" },
] as const;

export function TrendChart({
  series,
  legend = true,
}: {
  series: TrendPoint[];
  /** Hide when an adjacent legend with the same colors already names the series. */
  legend?: boolean;
}) {
  if (!series.length) {
    return <p className="ws-hint">No activity in this window.</p>;
  }
  const { top, ticks } = niceScale(Math.max(...series.map((point) => point.total)));
  const span = series.length > 1 ? series[1].ts - series[0].ts : 3600;
  const totals = {
    allow: series.reduce((sum, point) => sum + point.allow, 0),
    require_approval: series.reduce((sum, point) => sum + point.require_approval, 0),
    deny: series.reduce((sum, point) => sum + point.deny, 0),
  };
  const peak = series.reduce((best, point) => (point.total > best.total ? point : best), series[0]);
  const labelEvery = Math.max(1, Math.ceil(series.length / 8));
  const summary = `Decision volume: ${formatNumber(totals.allow)} allowed, ${formatNumber(totals.require_approval)} held for approval, ${formatNumber(totals.deny)} denied across ${series.length} buckets`;

  return (
    <figure className="ws-vchart">
      {legend ? (
      <ul className="ws-vchart-legend">
        {TREND_SERIES.map((item) => (
          <li key={item.key}>
            <span className={cn("ws-vchart-swatch", item.tone)} aria-hidden="true" />
            {item.label} <strong>{formatNumber(totals[item.key])}</strong>
          </li>
        ))}
      </ul>
      ) : null}
      <div className="ws-vchart-body">
        <div className="ws-vchart-yaxis" aria-hidden="true">
          {ticks.map((tick) => (
            <span key={tick} style={{ bottom: `${(tick / top) * 100}%` }}>
              {formatNumber(tick)}
            </span>
          ))}
        </div>
        <div className="ws-vchart-plot">
          {ticks.map((tick) => (
            <i key={tick} className="ws-vchart-grid" style={{ bottom: `${(tick / top) * 100}%` }} aria-hidden="true" />
          ))}
          <ol className="ws-vchart-cols" aria-label={summary}>
            {series.map((point, index) => {
              const when = bucketLabel(point.ts, span);
              const edge = index === 0 ? "is-first" : index === series.length - 1 ? "is-last" : undefined;
              if (point.total <= 0) {
                return <li key={point.ts} className="ws-vchart-col is-empty" aria-label={`${when}: no calls`} />;
              }
              return (
                <li
                  key={point.ts}
                  className={cn("ws-vchart-col", edge)}
                  tabIndex={0}
                  aria-label={`${when}: ${point.total} calls, ${point.allow} allowed, ${point.require_approval} held, ${point.deny} denied`}
                >
                  <span className="ws-vchart-bar" style={{ height: `${(point.total / top) * 100}%` }}>
                    {TREND_SERIES.map((item) =>
                      point[item.key] > 0 ? (
                        <span
                          key={item.key}
                          className={cn("ws-vchart-seg", item.tone, item.key === topKey(point) && "is-top")}
                          style={{ flexGrow: point[item.key] }}
                        />
                      ) : null,
                    )}
                    {point === peak ? <span className="ws-vchart-cap">{formatNumber(point.total)}</span> : null}
                    <span className="ws-vchart-tip" aria-hidden="true">
                    <strong>{when}</strong>
                    <span className="ws-vchart-tip-total">{formatNumber(point.total)} calls</span>
                    {TREND_SERIES.map((item) => (
                      <span key={item.key} className="ws-vchart-tip-row">
                        <span className={cn("ws-vchart-swatch", item.tone)} />
                        {item.label}
                        <b>{formatNumber(point[item.key])}</b>
                      </span>
                    ))}
                    </span>
                  </span>
                </li>
              );
            })}
          </ol>
        </div>
      </div>
      <div className="ws-vchart-xaxis" aria-hidden="true">
        {series.map((point, index) => (
          <span key={point.ts}>{index % labelEvery === 0 ? bucketLabel(point.ts, span) : ""}</span>
        ))}
      </div>
      <details className="ws-vchart-table">
        <summary>View as table</summary>
        <table>
          <thead>
            <tr>
              <th scope="col">Bucket</th>
              <th scope="col">Total</th>
              <th scope="col">Allow</th>
              <th scope="col">Approval</th>
              <th scope="col">Deny</th>
            </tr>
          </thead>
          <tbody>
            {series.map((point) => (
              <tr key={point.ts}>
                <th scope="row">{bucketLabel(point.ts, span)}</th>
                <td>{point.total}</td>
                <td>{point.allow}</td>
                <td>{point.require_approval}</td>
                <td>{point.deny}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>
    </figure>
  );
}

export function EmptyState({
  title,
  description,
  icon: Icon = Inbox,
  action,
}: {
  title: string;
  description?: ReactNode;
  icon?: ComponentType<{ className?: string; strokeWidth?: number }>;
  action?: ReactNode;
}) {
  return (
    <div className="ws-empty">
      <span className="ws-empty-icon">
        <Icon className="h-5 w-5" strokeWidth={1.7} />
      </span>
      <strong>{title}</strong>
      {description ? <p>{description}</p> : null}
      {action}
    </div>
  );
}

export function LoadingState({ rows = 3, label = "Loading gateway data" }: { rows?: number; label?: string }) {
  return (
    <div className="ws-loading-grid" aria-label={label} aria-busy="true">
      {Array.from({ length: rows }).map((_, index) => (
        <div className="ws-loading-card" key={index}>
          <div className="ws-skeleton ws-loading-line is-w1" />
          <div className="ws-skeleton ws-loading-line is-w2" />
          <div className="ws-skeleton ws-loading-line is-w3" />
        </div>
      ))}
    </div>
  );
}

export function InlineLoading({ label = "Loading" }: { label?: string }) {
  return (
    <span className="ws-status-line">
      <Loader2 className="h-3.5 w-3.5 animate-spin" /> {label}
    </span>
  );
}

export function ErrorState({
  failure,
  onRetry,
  compact = false,
}: {
  failure: ApiFailure;
  onRetry?: () => void;
  compact?: boolean;
}) {
  const hint = failureHint(failure);
  return (
    <div className={cn("ws-error-card", compact && "is-compact")}>
      <span className="ws-error-icon">
        {failure.kind === "network" ? (
          <ShieldAlert className="h-4 w-4" strokeWidth={1.8} />
        ) : (
          <CircleAlert className="h-4 w-4" strokeWidth={1.8} />
        )}
      </span>
      <div className="ws-error-copy">
        <strong>{failureTitle(failure)}</strong>
        <p>{failure.message}</p>
        {hint ? <p className="mt-1 opacity-80">{hint}</p> : null}
      </div>
      {onRetry ? (
        <button type="button" className="ws-btn is-sm" onClick={onRetry}>
          Retry
        </button>
      ) : null}
    </div>
  );
}

export function Banner({
  tone = "neutral",
  icon: Icon,
  children,
}: {
  tone?: "neutral" | "warn" | "error" | "purple";
  icon?: LucideIcon;
  children: ReactNode;
}) {
  return (
    <div className={cn("ws-banner", tone !== "neutral" && `is-${tone}`)}>
      {Icon ? <Icon className="mt-0.5 h-4 w-4 shrink-0" strokeWidth={1.8} /> : null}
      <div>{children}</div>
    </div>
  );
}

export function InferredBadge() {
  return <span className="ws-badge is-purple">inferred</span>;
}

export function LiveMeta({
  lastUpdated,
  isRefreshing,
  isStale,
  intervalLabel,
}: {
  lastUpdated: number | null;
  isRefreshing?: boolean;
  isStale?: boolean;
  intervalLabel?: string;
}) {
  return (
    <span className="ws-topbar-status" title={isStale ? "Showing the last successful snapshot" : undefined}>
      <Dot tone={isStale ? "warn" : isRefreshing ? "warn" : "live"} />
      <span>
        {isStale
          ? "Stale snapshot"
          : isRefreshing
            ? "Refreshing"
            : lastUpdated
              ? `Live · ${formatClock(lastUpdated)}`
              : null}
      </span>
      {!isStale && !isRefreshing && !lastUpdated ? (
        <SkeletonPill label="Loading live status" />
      ) : null}
      {intervalLabel ? <span className="hidden sm:inline">· {intervalLabel}</span> : null}
    </span>
  );
}

export function StaleBanner({
  failure,
  lastUpdated,
  onRetry,
}: {
  failure: ApiFailure;
  lastUpdated: number | null;
  onRetry: () => void;
}) {
  return (
    <div className="ws-banner is-warn">
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" strokeWidth={1.8} />
      <div className="flex-1">
        <strong>Live updates interrupted.</strong> Showing the last successful
        snapshot{lastUpdated ? ` from ${formatClock(lastUpdated)}` : ""}.{" "}
        {failure.message}
      </div>
      <button type="button" className="ws-btn is-sm" onClick={onRetry}>
        Retry
      </button>
    </div>
  );
}

export function SuccessNote({ children }: { children: ReactNode }) {
  return (
    <div className="ws-banner is-purple">
      <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" strokeWidth={1.8} />
      <div>{children}</div>
    </div>
  );
}

export function Sparkline({
  values,
  tone = "navy",
}: {
  values: number[];
  tone?: "allow" | "hold" | "deny" | "navy";
}) {
  const max = Math.max(...values, 0);
  if (!values.length || max <= 0) {
    return (
      <span className="ws-sparkline is-empty" role="img" aria-label="No activity in this window" />
    );
  }
  return (
    <span className={cn("ws-sparkline", `is-${tone}`)} aria-hidden="true">
      {values.slice(-18).map((value, index) => (
        <span
          key={index}
          style={{ height: `${value > 0 ? (value / max) * 100 : 0}%` }}
        />
      ))}
    </span>
  );
}

export type PipelineTone = "ok" | "warn" | "error" | "idle";

export function SecurityPipeline({
  nodes,
}: {
  nodes: Array<{
    key: string;
    label: string;
    detail: string;
    icon?: LucideIcon;
    tone?: PipelineTone;
  }>;
}) {
  return (
    <ol className="ws-pipeline" aria-label="Security pipeline">
      {nodes.map((node, index) => {
        const Icon = node.icon;
        return (
          <li
            key={node.key}
            className={cn("ws-pipeline-node", `is-${node.tone ?? "idle"}`)}
          >
            <span className="ws-pipeline-index">
              {String(index + 1).padStart(2, "0")}
            </span>
            <span className="ws-pipeline-icon">
              {Icon ? <Icon className="h-4 w-4" strokeWidth={1.7} /> : null}
            </span>
            <span className="ws-pipeline-copy">
              <strong>{node.label}</strong>
              <span>{node.detail}</span>
            </span>
            {index < nodes.length - 1 ? (
              <ChevronRight className="ws-pipeline-arrow h-4 w-4" aria-hidden="true" />
            ) : null}
          </li>
        );
      })}
    </ol>
  );
}

export function ProvenanceIndicator({
  source,
  counts,
}: {
  source?: string;
  counts?: Array<{ source: string; count: number }>;
}) {
  const order = ["user", "system", "trusted_tool", "untrusted"];
  const total = counts?.reduce((sum, row) => sum + row.count, 0) ?? 0;
  const active = source?.toLowerCase();

  return (
    <div className="ws-prov" aria-label="Provenance classification">
      <div className="ws-prov-head">
        <span className="ws-label">Provenance</span>
        {source ? (
          <span className="ws-prov-active">
            resolved · {sourceLabel(source)}
          </span>
        ) : null}
      </div>
      {counts && total > 0 ? (
        <div className="ws-prov-bars">
          {order.map((key) => {
            const count = counts.find((row) => row.source === key)?.count ?? 0;
            return (
              <span
                key={key}
                className={cn("ws-prov-bar", `is-${key}`)}
                style={{ flexGrow: Math.max(count, 0.0001) }}
                title={`${sourceLabel(key)}: ${formatNumber(count)}`}
              >
                <span>{sourceLabel(key)}</span>
                <strong>{formatNumber(count)}</strong>
              </span>
            );
          })}
        </div>
      ) : (
        <div className="ws-prov-scale">
          {order.map((key) => (
            <span
              key={key}
              className={cn(
                "ws-prov-pill",
                `is-${key}`,
                active === key && "is-active",
              )}
            >
              {sourceLabel(key)}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

export function PolicyStep({
  step,
  label,
  description,
  rule,
}: {
  step: number;
  label: ReactNode;
  description: ReactNode;
  rule?: ReactNode;
}) {
  return (
    <li className="ws-policy-step">
      <span className="ws-policy-step-index">{String(step).padStart(2, "0")}</span>
      <div className="ws-policy-step-copy">
        <strong>{label}</strong>
        <span>{description}</span>
        {rule ? <code className="ws-policy-step-rule">{rule}</code> : null}
      </div>
    </li>
  );
}

export function EventRow({
  decision,
  tool,
  meta,
  time,
  source,
  href,
}: {
  decision: string;
  tool: string;
  meta?: ReactNode;
  time?: ReactNode;
  source?: string;
  href?: string;
}) {
  const body = (
    <>
      <DecisionBadge decision={decision} short />
      <span className="ws-event-tool">
        <strong>{tool}</strong>
        {meta ? <span>{meta}</span> : null}
      </span>
      {source ? <SourceBadge source={source} /> : null}
      {time ? <span className="ws-event-time">{time}</span> : null}
      {href ? <ChevronRight className="h-3.5 w-3.5" aria-hidden="true" /> : null}
    </>
  );
  if (href) {
    return (
      <Link href={href} className="ws-event-row">
        {body}
      </Link>
    );
  }
  return <div className="ws-event-row">{body}</div>;
}

export function NavyFeaturePanel({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  return <section className={cn("ws-navy-panel", className)}>{children}</section>;
}

export function PurpleActionButton({
  children,
  className,
  onClick,
  disabled,
  type = "button",
}: {
  children: ReactNode;
  className?: string;
  onClick?: () => void;
  disabled?: boolean;
  type?: "button" | "submit";
}) {
  return (
    <button
      type={type}
      className={cn("ws-btn is-purple", className)}
      onClick={onClick}
      disabled={disabled}
    >
      {children}
    </button>
  );
}

export function LimeStatusIndicator({
  label,
  detail,
}: {
  label: ReactNode;
  detail?: ReactNode;
}) {
  return (
    <span className="ws-lime-indicator">
      <Dot tone="ok" />
      <span>
        <strong>{label}</strong>
        {detail ? <span>{detail}</span> : null}
      </span>
    </span>
  );
}

export function GatewayStatus({
  state,
  detail,
}: {
  state: "live" | "offline" | "checking";
  detail?: ReactNode;
}) {
  return (
    <span
      className={cn("ws-gateway-status", `is-${state}`)}
      title={typeof detail === "string" ? detail : undefined}
    >
      <Dot tone={state === "live" ? "live" : state === "offline" ? "error" : "warn"} />
      <span>
        {state === "live"
          ? "Gateway live"
          : state === "offline"
            ? "Gateway offline"
            : "Connecting"}
      </span>
    </span>
  );
}

export function TrustBadge({ source }: { source: string }) {
  return <SourceBadge source={source} />;
}

export function BrandCard({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  return <section className={cn("ws-card ws-brand-card", className)}>{children}</section>;
}

export function EvidencePanel({
  title,
  source,
  children,
  className,
}: {
  title: ReactNode;
  source?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={cn("ws-evidence-panel", className)}>
      <header>
        <strong>{title}</strong>
        {source ? <span>{source}</span> : null}
      </header>
      <div>{children}</div>
    </section>
  );
}

export function InspectorPanel({
  title,
  subtitle,
  actions,
  children,
  className,
}: {
  title: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <aside className={cn("ws-inspector-panel", className)}>
      <div className="ws-inspector-head">
        <div>
          <strong>{title}</strong>
          {subtitle ? <span>{subtitle}</span> : null}
        </div>
        {actions ? <div className="ws-row">{actions}</div> : null}
      </div>
      <div className="ws-inspector-body">{children}</div>
    </aside>
  );
}
