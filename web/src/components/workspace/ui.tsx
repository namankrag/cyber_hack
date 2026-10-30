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
    severity === "high" ? "is-deny" : severity === "medium" ? "is-hold" : "is-allow";
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

export function StatCard({
  label,
  value,
  meta,
  icon: Icon,
  tone,
  badge,
  visual,
}: {
  label: string;
  value: ReactNode;
  meta?: ReactNode;
  icon?: LucideIcon;
  tone?: "purple" | "lime" | "navy" | "peach" | "cream" | "blue";
  badge?: ReactNode;
  visual?: ReactNode;
}) {
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
            "rounded-[11px] border px-3 py-2.5",
            detection.error
              ? "border-[#efd28a] bg-[#fffaf0]"
              : detection.is_threat
                ? "border-[#efb5ae] bg-[#fff7f5]"
                : "border-[#d9d6d0] bg-[#f8f7f4]",
          )}
        >
          <div className="ws-between">
            <span className="ws-mono text-[10.5px] font-semibold">
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
              <span className="ws-mono text-[10px] text-[#6f6c66]">
                {detection.score.toFixed(2)}
              </span>
            </div>
          </div>
          {detection.error ? (
            <p className="mt-1.5 text-[10.5px] leading-relaxed text-[#6b4a00]">
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
}: {
  allow: number;
  hold: number;
  deny: number;
  labels?: boolean;
}) {
  const total = allow + hold + deny;
  if (total <= 0) {
    return (
      <div className="ws-dist" aria-label="No decisions in this window">
        <span style={{ width: "100%", background: "#e7e4de" }} />
      </div>
    );
  }
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
          </span>
          <span className="ws-legend-item">
            <span className="ws-legend-swatch is-hold" /> Approval {formatNumber(hold)}
          </span>
          <span className="ws-legend-item">
            <span className="ws-legend-swatch is-deny" /> Deny {formatNumber(deny)}
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
  rows: Array<{ label: string; value: number; note?: string; tone?: "navy" | "purple" | "lime" | "red" }>;
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
          <span className="ws-bar-track">
            <span
              className={cn("ws-bar-fill", row.tone && `is-${row.tone}`)}
              style={{ width: `${Math.max(2, (row.value / max) * 100)}%` }}
            />
          </span>
          <span className="ws-mono text-[9.5px] text-[#6f6c66]">
            {row.note ?? formatNumber(row.value)}
          </span>
        </div>
      ))}
    </div>
  );
}

export function TrendChart({
  series,
}: {
  series: Array<{
    ts: number;
    total: number;
    allow: number;
    deny: number;
    require_approval: number;
    threats: number;
  }>;
}) {
  if (!series.length) {
    return <p className="ws-hint">No bucketed traffic in this window.</p>;
  }
  const max = Math.max(...series.map((point) => point.total), 1);
  return (
    <div>
      <div className="ws-chart" aria-label="Decision volume over time">
        {series.map((point) => {
          const dominant =
            point.deny >= point.require_approval && point.deny >= point.allow
              ? "is-deny"
              : point.require_approval >= point.allow
                ? "is-hold"
                : "is-allow";
          return (
            <span
              key={point.ts}
              className={cn("ws-chart-bar", point.total > 0 && dominant)}
              style={{ height: `${Math.max(2, (point.total / max) * 100)}%` }}
              title={`${formatClock(point.ts * 1000)} · ${point.total} calls · ${point.allow} allow · ${point.require_approval} hold · ${point.deny} deny`}
            />
          );
        })}
      </div>
      <div className="ws-chart-axis">
        <span>{formatClock(series[0].ts * 1000)}</span>
        <span>{formatClock(series[series.length - 1].ts * 1000)}</span>
      </div>
    </div>
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
          <div className="ws-skeleton ws-loading-line" style={{ width: "42%" }} />
          <div className="ws-skeleton ws-loading-line" style={{ width: "66%", height: 24 }} />
          <div className="ws-skeleton ws-loading-line" style={{ width: "80%" }} />
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
    <div className={cn("ws-error-card", compact && "py-2.5")}>
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
              : "Connecting"}
      </span>
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
  tone = "purple",
}: {
  values: number[];
  tone?: "purple" | "lime" | "peach" | "navy";
}) {
  const max = Math.max(...values, 1);
  return (
    <span className={cn("ws-sparkline", `is-${tone}`)} aria-hidden="true">
      {values.slice(-18).map((value, index) => (
        <span
          key={index}
          style={{ height: `${Math.max(8, (value / max) * 100)}%` }}
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
