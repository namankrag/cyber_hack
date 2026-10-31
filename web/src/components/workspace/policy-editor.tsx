"use client";

import { History, Loader2, Lock, PencilLine, RotateCcw, ScanSearch, Upload } from "lucide-react";
import { useState } from "react";
import { apiPost } from "@/lib/api/client";
import { toApiFailure, type ApiFailure } from "@/lib/api/errors";
import type {
  PolicyHistoryResponse,
  PolicyImpactMetrics,
  PolicyPreviewResponse,
  PolicyResponse,
} from "@/lib/api/types";
import { useLiveData } from "@/lib/hooks/use-live-data";
import { cn } from "@/lib/utils";
import { useSession } from "./session-context";
import { ConfirmDialog } from "./confirm-dialog";
import {
  Banner,
  Card,
  CardBody,
  CardHead,
  DecisionBadge,
  EmptyState,
  ErrorState,
  SuccessNote,
} from "@/components/workspace/ui";

/** Example edits: exact, targeted text changes; reported when they don't apply. */
const EXAMPLES: Array<{ label: string; pattern: RegExp; replace: string }> = [
  {
    label: "Allow transfer_funds",
    pattern: /(transfer_funds:\s*\n(?:[ \t]+.*\n)*?[ \t]+allow:\s*)false/,
    replace: "$1true",
  },
  {
    label: "Stop requiring approval for send_email",
    pattern: /(send_email:\s*\n(?:[ \t]+.*\n)*?[ \t]+require_approval:\s*)true/,
    replace: "$1false",
  },
  {
    label: "Let untrusted content use high-risk tools",
    pattern: /(on_untrusted_high_sensitivity:\s*)deny/,
    replace: "$1allow",
  },
];

const METRICS: Array<{ key: keyof PolicyImpactMetrics; label: string; lowerIsBetter: boolean }> = [
  { key: "attack_success", label: "Attacks that succeed", lowerIsBetter: true },
  { key: "attack_denied", label: "Attacks denied", lowerIsBetter: false },
  { key: "attack_held", label: "Attacks held for a human", lowerIsBetter: false },
  { key: "benign_denied", label: "Benign calls wrongly denied", lowerIsBetter: true },
  { key: "benign_held", label: "Benign calls held", lowerIsBetter: true },
  { key: "approval_correctness", label: "High-impact calls held correctly", lowerIsBetter: false },
  { key: "expected_match", label: "Verdicts matching expectation", lowerIsBetter: false },
];

function pct(v: number | null): string {
  return v == null ? "—" : `${(v * 100).toFixed(1)}%`;
}

export function PolicyEditor({ policy, onPublished }: { policy: PolicyResponse; onPublished: () => void }) {
  const { role, requireAdmin, noteUnauthorized } = useSession();
  const isAdmin = role === "admin";
  const pinned = policy.digest_pinned;
  const history = useLiveData<PolicyHistoryResponse>("/v1/policy/history", { intervalMs: 60_000 });

  const [draft, setDraft] = useState(policy.yaml);
  const [baseSha, setBaseSha] = useState(policy.digest);
  const [preview, setPreview] = useState<PolicyPreviewResponse | null>(null);
  const [previewFor, setPreviewFor] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);
  const [failure, setFailure] = useState<ApiFailure | null>(null);
  const [hint, setHint] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<null | { kind: "publish" } | { kind: "rollback"; version: string }>(null);
  const [working, setWorking] = useState(false);
  const [success, setSuccess] = useState<string | null>(null);

  // A newly published (or externally changed) policy becomes the new base.
  // Adjusting state during render (not in an effect) is React's pattern for
  // resetting derived state when a prop changes.
  if (policy.digest !== baseSha) {
    setDraft(policy.yaml);
    setBaseSha(policy.digest);
    setPreview(null);
    setPreviewFor(null);
  }

  const dirty = draft !== policy.yaml;
  const previewCurrent = preview != null && previewFor === draft;

  const check = async () => {
    setChecking(true);
    setFailure(null);
    setHint(null);
    try {
      const result = await apiPost<PolicyPreviewResponse>("/v1/policy/preview", { yaml: draft }, undefined, 30_000);
      setPreview(result);
      setPreviewFor(draft);
    } catch (error) {
      setPreview(null);
      setFailure(toApiFailure(error));
    } finally {
      setChecking(false);
    }
  };

  const applyExample = (example: (typeof EXAMPLES)[number]) => {
    if (!example.pattern.test(draft)) {
      setHint(`"${example.label}" doesn't apply to the current draft (already changed?).`);
      return;
    }
    setHint(null);
    setDraft(draft.replace(example.pattern, example.replace));
  };

  const publish = async () => {
    setWorking(true);
    setFailure(null);
    try {
      await apiPost("/v1/admin/policy/publish", { yaml: draft, base_sha256: baseSha }, undefined, 30_000);
      setSuccess("Published. The gateway is enforcing the new rules now; the previous version is kept in history.");
      setConfirm(null);
      onPublished();
      void history.refresh();
    } catch (error) {
      noteUnauthorized(error);
      setFailure(toApiFailure(error));
      setConfirm(null);
    } finally {
      setWorking(false);
    }
  };

  const rollback = async (version: string) => {
    setWorking(true);
    setFailure(null);
    try {
      await apiPost("/v1/admin/policy/rollback", { version, base_sha256: baseSha }, undefined, 30_000);
      setSuccess(`Rolled back to ${version}. The gateway is enforcing it now.`);
      setConfirm(null);
      onPublished();
      void history.refresh();
    } catch (error) {
      noteUnauthorized(error);
      setFailure(toApiFailure(error));
      setConfirm(null);
    } finally {
      setWorking(false);
    }
  };

  const worse =
    preview &&
    (preview.metrics.draft.attack_success ?? 0) > (preview.metrics.active.attack_success ?? 0);

  return (
    <>
      <Card>
        <CardHead
          title="Change the policy"
          icon={PencilLine}
          subtitle="Edit → check the impact on the benchmark → publish. Anyone can preview; publishing needs an admin."
        />
        <CardBody>
          {pinned ? (
            <Banner tone="warn" icon={Lock}>
              <strong>Pinned policy.</strong> AGENTSHIELD_POLICY_SHA256 is set, so the console can preview changes but
              cannot publish them. Change the rules through review and redeploy.
            </Banner>
          ) : null}
          <div className="ws-policy-examples">
            <span className="ws-label">Try a risky change</span>
            {EXAMPLES.map((example) => (
              <button key={example.label} type="button" className="ws-btn is-sm is-ghost" onClick={() => applyExample(example)}>
                {example.label}
              </button>
            ))}
            {dirty ? (
              <button
                type="button"
                className="ws-btn is-sm is-ghost"
                onClick={() => {
                  setDraft(policy.yaml);
                  setPreview(null);
                  setHint(null);
                }}
              >
                <RotateCcw className="h-3.5 w-3.5" /> Reset draft
              </button>
            ) : null}
          </div>
          {hint ? <p className="ws-hint">{hint}</p> : null}
          <textarea
            className="ws-policy-editor"
            value={draft}
            onChange={(event) => setDraft(event.target.value)}
            spellCheck={false}
            rows={18}
            aria-label="Draft policy YAML"
          />
          <div className="ws-mcp-composer-actions">
            <button type="button" className="ws-btn" onClick={() => void check()} disabled={checking}>
              {checking ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ScanSearch className="h-3.5 w-3.5" />}
              Check impact
            </button>
            <button
              type="button"
              className={cn("ws-btn", previewCurrent && dirty && !pinned ? "is-lime" : "")}
              disabled={!previewCurrent || !dirty || pinned || working}
              onClick={() => requireAdmin(() => setConfirm({ kind: "publish" }))}
              title={!previewCurrent ? "Check the impact of this exact draft first" : undefined}
            >
              {!isAdmin ? <Lock className="h-3.5 w-3.5" /> : <Upload className="h-3.5 w-3.5" />}
              {!isAdmin ? "Admin only · Publish" : "Publish"}
            </button>
            <span className="ws-hint">
              {dirty ? (previewCurrent ? "Impact checked for this draft." : "Draft changed: check its impact before publishing.") : "No changes yet."}
            </span>
          </div>

          {failure ? <ErrorState failure={failure} compact /> : null}
          {success ? <SuccessNote>{success}</SuccessNote> : null}

          {preview && previewCurrent ? (
            <div className="ws-policy-impact">
              {preview.identical ? (
                <p className="ws-hint">The draft is identical to the active policy.</p>
              ) : (
                <>
                  <div className={cn("ws-policy-impact-head", worse ? "is-worse" : "is-ok")}>
                    <strong>
                      {worse
                        ? "This change lets more attacks through."
                        : preview.changed.length
                          ? "This change shifts some verdicts. Review them below."
                          : "No benchmark verdict changes."}
                    </strong>
                    <span>
                      Re-ran {preview.cases} benchmark cases against the active policy and this draft (keyword detector,
                      nothing written to the audit trail).
                    </span>
                  </div>
                  <table className="ws-table ws-policy-metrics">
                    <thead>
                      <tr>
                        <th>Benchmark metric</th>
                        <th>Active</th>
                        <th>Draft</th>
                      </tr>
                    </thead>
                    <tbody>
                      {METRICS.map((m) => {
                        const a = preview.metrics.active[m.key];
                        const d = preview.metrics.draft[m.key];
                        const delta = a != null && d != null ? d - a : 0;
                        const bad = delta !== 0 && (m.lowerIsBetter ? delta > 0 : delta < 0);
                        return (
                          <tr key={m.key}>
                            <td>{m.label}</td>
                            <td className="font-mono">{pct(a)}</td>
                            <td className={cn("font-mono", delta !== 0 && (bad ? "ws-policy-bad" : "ws-policy-good"))}>
                              {pct(d)}
                              {delta !== 0 ? ` (${delta > 0 ? "+" : ""}${(delta * 100).toFixed(1)})` : ""}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                  {preview.changed.length ? (
                    <div className="ws-table-wrap ws-policy-changed">
                      <table className="ws-table">
                        <thead>
                          <tr>
                            <th>Case</th>
                            <th>Type</th>
                            <th>Tool</th>
                            <th>Expected</th>
                            <th>Active</th>
                            <th>Draft</th>
                          </tr>
                        </thead>
                        <tbody>
                          {preview.changed.map((c) => (
                            <tr key={c.id}>
                              <td className="font-mono ws-fs-meta">{c.id}</td>
                              <td className="ws-fs-meta">{c.attack_type ?? c.label}</td>
                              <td className="font-mono ws-fs-meta">{c.tool}</td>
                              <td><DecisionBadge decision={c.expected} short /></td>
                              <td><DecisionBadge decision={c.before} short /></td>
                              <td><DecisionBadge decision={c.after} short /></td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : null}
                  <details className="ws-vchart-table">
                    <summary>View the diff</summary>
                    <pre className="ws-doclab-diff">
                      {preview.diff.split("\n").map((line, index) => (
                        <span
                          key={index}
                          className={cn(
                            line.startsWith("+") && !line.startsWith("+++") && "is-add",
                            line.startsWith("-") && !line.startsWith("---") && "is-del",
                            line.startsWith("@@") && "is-hunk",
                          )}
                        >
                          {line}
                          {"\n"}
                        </span>
                      ))}
                    </pre>
                  </details>
                </>
              )}
            </div>
          ) : null}
        </CardBody>
      </Card>

      <Card>
        <CardHead title="Policy history" icon={History} subtitle="Every publish and rollback, with the previous version kept for one-click restore" />
        <CardBody>
          {history.failure && !history.data ? (
            <ErrorState failure={history.failure} onRetry={() => void history.refresh()} compact />
          ) : history.data && history.data.changes.length ? (
            <ul className="ws-policy-history">
              {history.data.changes.map((change) => (
                <li key={`${change.at}-${change.to_sha256}`}>
                  <span className={cn("ws-badge", change.action === "publish" ? "is-hold" : "is-allow")}>{change.action}</span>
                  <span className="ws-hint">{new Date(change.at * 1000).toLocaleString()}</span>
                  <code>
                    {change.from_sha256.slice(0, 8)} → {change.to_sha256.slice(0, 8)}
                  </code>
                  <span className="ws-hint">
                    attacks succeed {pct(change.impact.active.attack_success)} → {pct(change.impact.draft.attack_success)}
                  </span>
                  <button
                    type="button"
                    className="ws-btn is-sm is-ghost"
                    disabled={pinned || working}
                    onClick={() => requireAdmin(() => setConfirm({ kind: "rollback", version: change.previous_version }))}
                  >
                    {!isAdmin ? <Lock className="h-3.5 w-3.5" /> : <RotateCcw className="h-3.5 w-3.5" />} Restore the version before this
                  </button>
                </li>
              ))}
            </ul>
          ) : (
            <EmptyState icon={History} title="No policy changes yet" description="Published changes and rollbacks appear here with their benchmark impact." />
          )}
        </CardBody>
      </Card>

      <ConfirmDialog
        open={confirm != null}
        title={confirm?.kind === "rollback" ? "Restore this policy version?" : "Publish this policy?"}
        description={
          confirm?.kind === "rollback"
            ? "The gateway will enforce the restored rules immediately. The current version is kept in history."
            : worse
              ? `Warning: on the benchmark this draft lets more attacks through (${pct(preview?.metrics.active.attack_success ?? null)} → ${pct(preview?.metrics.draft.attack_success ?? null)}). The gateway will enforce it immediately; you can roll back from history.`
              : "The gateway will enforce the new rules immediately. The current version is kept in history for rollback."
        }
        confirmLabel={confirm?.kind === "rollback" ? "Restore" : "Publish"}
        onConfirm={() => void (confirm?.kind === "rollback" ? rollback(confirm.version) : publish())}
        onCancel={() => {
          if (!working) setConfirm(null);
        }}
        pending={working}
        tone={worse || confirm?.kind === "rollback" ? "danger" : "primary"}
      />
    </>
  );
}
