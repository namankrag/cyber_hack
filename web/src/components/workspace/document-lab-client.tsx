"use client";

import {
  ArrowDown,
  Bug,
  CheckCircle2,
  Download,
  FileSearch,
  FileText,
  Fingerprint,
  Loader2,
  ScanSearch,
  ShieldCheck,
  Upload,
  Wrench,
  XCircle,
} from "lucide-react";
import Link from "next/link";
import { useCallback, useEffect, useRef, useState, type DragEvent } from "react";
import { apiPost } from "@/lib/api/client";
import { toApiFailure, type ApiFailure } from "@/lib/api/errors";
import { formatNumber } from "@/lib/api/format";
import type {
  CodeIssue,
  CodeTarget,
  DocumentAnalysis,
  DocumentDecision,
  DocumentSamplesResponse,
  DetectorVerdict,
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
  PageHeader,
  ReasonList,
  SeverityBadge,
  SourceBadge,
} from "@/components/workspace/ui";

const ACCEPT = ".pdf,.txt,.md,.html,.htm,.eml,.csv,.json,.log,.xml";
const DEFAULT_MAX_BYTES = 2 * 1024 * 1024;
const ANALYZE_TIMEOUT_MS = 70_000;

const SAMPLE_PDFS = [
  { href: "/samples/poisoned_vendor_report.pdf", label: "Poisoned vendor report", note: "hidden data-exfiltration order" },
  { href: "/samples/northwind_invoice.pdf", label: "Invoice with a hidden wire", note: "hidden USD 48,500 transfer" },
  { href: "/samples/reworded_ledger_request.pdf", label: "Politely worded data theft", note: "no trigger words: the LLM layer catches it" },
  { href: "/samples/hindi_upi_refund.pdf", label: "Hindi UPI refund scam", note: "Hinglish lure: Rs. 4999 to a UPI ID" },
  { href: "/samples/clean_meeting_notes.pdf", label: "Clean meeting notes", note: "no attack, control case" },
];

type Phase = "idle" | "running" | "done" | "error";

function readAsBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error("The browser could not read this file."));
    reader.onload = () => {
      const result = String(reader.result ?? "");
      resolve(result.slice(result.indexOf(",") + 1));
    };
    reader.readAsDataURL(file);
  });
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function DocumentLabClient() {
  const samples = useLiveData<DocumentSamplesResponse>("/v1/document/samples", {
    intervalMs: 300_000,
  });
  const [phase, setPhase] = useState<Phase>("idle");
  const [slow, setSlow] = useState(false);
  const [elapsed, setElapsed] = useState(0);
  const [lastDuration, setLastDuration] = useState<number | null>(null);
  const [label, setLabel] = useState<string | null>(null);
  const [result, setResult] = useState<DocumentAnalysis | null>(null);
  const [failure, setFailure] = useState<ApiFailure | null>(null);
  const [localError, setLocalError] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const inFlight = useRef<AbortController | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);
  const maxBytes = samples.data?.max_file_bytes ?? DEFAULT_MAX_BYTES;

  useEffect(() => () => inFlight.current?.abort(), []);

  const analyze = useCallback(async (body: Record<string, unknown>, name: string) => {
    inFlight.current?.abort();
    const controller = new AbortController();
    inFlight.current = controller;
    setPhase("running");
    setSlow(false);
    setLabel(name);
    setFailure(null);
    setLocalError(null);
    const slowTimer = window.setTimeout(() => setSlow(true), 1500);
    const startedAt = Date.now();
    setElapsed(0);
    const tick = window.setInterval(() => setElapsed(Math.floor((Date.now() - startedAt) / 1000)), 250);
    try {
      const response = await apiPost<DocumentAnalysis>(
        "/v1/document/analyze",
        body,
        controller.signal,
        ANALYZE_TIMEOUT_MS,
      );
      if (inFlight.current !== controller) return;
      setResult(response);
      setPhase("done");
    } catch (error) {
      if (inFlight.current !== controller) return;
      setFailure(toApiFailure(error));
      setPhase("error");
    } finally {
      window.clearTimeout(slowTimer);
      window.clearInterval(tick);
      setLastDuration((Date.now() - startedAt) / 1000);
      if (inFlight.current === controller) inFlight.current = null;
    }
  }, []);

  const onFile = useCallback(
    async (file: File | undefined) => {
      if (!file) return;
      if (file.size > maxBytes) {
        setLocalError(`${file.name} is ${formatBytes(file.size)}; the limit is ${formatBytes(maxBytes)}.`);
        return;
      }
      try {
        const content = await readAsBase64(file);
        await analyze({ filename: file.name, content_base64: content }, file.name);
      } catch (error) {
        setLocalError(error instanceof Error ? error.message : "Could not read this file.");
      }
    },
    [analyze, maxBytes],
  );

  const onDrop = (event: DragEvent<HTMLLabelElement>) => {
    event.preventDefault();
    setDragOver(false);
    void onFile(event.dataTransfer.files?.[0]);
  };

  const running = phase === "running";

  return (
    <div className="ws-stack">
      <PageHeader
        eyebrow="Document Lab"
        title={
          <>
            Upload a document. <em>Watch both layers work.</em>
          </>
        }
        description="AgentShield decides every action the document tries to make an agent take, before any tool runs. When it blocks an attack on a governed tool, it traces the attack to that tool's code: PatchProof proves the weakness with a real exploit, patches it and verifies the fix. Every step below is computed live by the gateway."
      />

      <Card>
        <CardHead
          title="1 · Choose a document"
          subtitle={`PDF or text, up to ${formatBytes(maxBytes)}. The file is read on the gateway and never executed.`}
          icon={Upload}
        />
        <CardBody>
          <div className={cn("ws-doclab-intake", result && !running && "is-compact")}>
            <label
              className={cn("ws-doclab-drop", dragOver && "is-over", running && "is-busy")}
              onDragOver={(event) => {
                event.preventDefault();
                setDragOver(true);
              }}
              onDragLeave={() => setDragOver(false)}
              onDrop={onDrop}
            >
              <input
                ref={fileInput}
                type="file"
                accept={ACCEPT}
                className="sr-only"
                disabled={running}
                onChange={(event) => {
                  void onFile(event.target.files?.[0]);
                  event.target.value = "";
                }}
              />
              <span className="ws-doclab-drop-icon">
                {running ? <Loader2 className="h-5 w-5 animate-spin" /> : <FileSearch className="h-5 w-5" />}
              </span>
              <strong>
                {running
                  ? `Analyzing ${label ?? "document"}… ${elapsed}s`
                  : result
                    ? "Analyze another document: drop a file or click"
                    : "Drop a file here or click to upload"}
              </strong>
              <span>{ACCEPT.split(",").join(" ")}</span>
            </label>

            <div className="ws-doclab-samples">
              <p className="ws-label">Or run a built-in sample</p>
              <div className="ws-doclab-sample-list">
                {(samples.data?.samples ?? []).map((sample) => (
                  <button
                    key={sample.id}
                    type="button"
                    className="ws-btn is-sm is-ghost"
                    disabled={running}
                    onClick={() => void analyze({ sample_id: sample.id }, sample.filename)}
                  >
                    <FileText className="h-3.5 w-3.5" /> {sample.title}
                  </button>
                ))}
                {samples.failure && !samples.data ? (
                  <span className="ws-hint">Samples unavailable: {samples.failure.message}</span>
                ) : null}
              </div>
              <p className="ws-label">Sample PDFs to upload</p>
              <ul className="ws-doclab-pdfs">
                {SAMPLE_PDFS.map((pdf) => (
                  <li key={pdf.href}>
                    <a href={pdf.href} download>
                      <Download className="h-3.5 w-3.5" /> {pdf.label}
                    </a>
                    <span>{pdf.note}</span>
                  </li>
                ))}
              </ul>
              <p className="ws-hint">
                The attack PDFs hide their instruction as invisible white text: a person
                reading the page sees nothing, but an agent reading the text layer does.
              </p>
            </div>
          </div>
          {localError ? <p className="ws-doclab-local-error">{localError}</p> : null}
        </CardBody>
      </Card>

      {running ? (
        <Card>
          <CardBody>
            <ol className="ws-doclab-progress" aria-live="polite">
              <li className="is-active">
                <Loader2 className="h-3.5 w-3.5 animate-spin" /> Runtime guard · extracting text, scanning for
                injected instructions and deciding each action
              </li>
              <li className={cn(slow && "is-active")}>
                {slow ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <span className="ws-doclab-dot" />}
                Root-cause fix · if anything is blocked: exploit-proving, patching and verifying the targeted
                code (the first run takes a few seconds; later runs reuse the verified result)
              </li>
            </ol>
          </CardBody>
        </Card>
      ) : null}

      {phase === "error" && failure ? (
        <ErrorState failure={failure} />
      ) : null}

      {!result && !running && phase !== "error" ? (
        <Card>
          <EmptyState
            icon={FileSearch}
            title="No document analyzed yet"
            description="Upload a file or pick a sample. Results show the document, every decision AgentShield made with its reasons, and, when a governed tool was attacked, the exploit, patch and verification for that tool's code."
          />
        </Card>
      ) : null}

      {result && !running ? <Results result={result} seconds={lastDuration} /> : null}
    </div>
  );
}

function Results({ result, seconds }: { result: DocumentAnalysis; seconds: number | null }) {
  const { document: doc, ps1, ps2 } = result;
  const blocked = ps1.decisions.filter((d) => d.would_block);
  return (
    <>
      <div className="ws-doclab-docstrip">
        <FileText className="h-4 w-4" />
        <strong className="ws-truncate">{doc.filename}</strong>
        <span>{doc.kind.toUpperCase()}</span>
        {doc.pages != null ? <span>{doc.pages} page{doc.pages === 1 ? "" : "s"}</span> : null}
        <span>{formatNumber(doc.chars)} chars{doc.truncated ? " (first 60k scanned)" : ""}</span>
        <span className="ws-mono">sha256 {doc.sha256.slice(0, 12)}…</span>
      </div>

      <VerdictHero result={result} seconds={seconds} />

      <DocumentView result={result} />

      <div id="doclab-runtime" className="ws-anchor" />
      <StageLabel layer="Runtime guard" title="AgentShield" detail="Decide every action before any tool runs" />

      <div className="ws-grid ws-doclab-ps1">
        <Card>
          <CardHead title="2 · Provenance and threat scan" icon={ScanSearch} subtitle={`${ps1.detection.sentences_scanned} sentences scanned · detectors: ${ps1.detection.detectors.join(", ")}`} />
          <CardBody>
            <div className="ws-doclab-prov">
              <SourceBadge source={ps1.provenance.source} />
              <p>{ps1.provenance.reason}</p>
            </div>
            <DocumentScan verdicts={ps1.detection.document_scan} />
            {ps1.detection.flagged.length ? (
              <ul className="ws-doclab-flagged">
                {ps1.detection.flagged.map((item, index) => (
                  <li key={index} className={cn(item.threat && "is-threat")}>
                    <blockquote>{item.text}</blockquote>
                    <div className="ws-doclab-signals">
                      <span className="ws-badge is-deny">score {item.score.toFixed(2)}</span>
                      {item.signals.map((signal) => (
                        <span key={signal} className="ws-doclab-signal">{signal}</span>
                      ))}
                    </div>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="ws-hint">No sentence matched the keyword detector.</p>
            )}
            {ps1.detection.flagged_total > ps1.detection.flagged.length ? (
              <p className="ws-hint">
                Showing {ps1.detection.flagged.length} of {ps1.detection.flagged_total} flagged sentences.
              </p>
            ) : null}
          </CardBody>
        </Card>

        <Card>
          <CardHead
            title="3 · What the document made the agent try"
            icon={ShieldCheck}
            subtitle={`${ps1.summary.allow ?? 0} allowed · ${ps1.summary.require_approval ?? 0} held · ${ps1.summary.deny ?? 0} denied${ps1.enforced ? "" : " · enforcement OFF (would-be verdicts recorded)"}`}
          />
          <CardBody>
            <p className="ws-hint">{ps1.agent_note}</p>
            <ol className="ws-doclab-decisions">
              {ps1.decisions.map((decision, index) => (
                <DecisionRow key={decision.call_id} decision={decision} index={index} />
              ))}
            </ol>
          </CardBody>
        </Card>
      </div>

      <div className={cn("ws-doclab-bridge", ps2.triggered && "is-triggered")}>
        <ArrowDown className="h-4 w-4" />
        {ps2.triggered ? (
          <span>
            <strong>Bridge:</strong> AgentShield blocked{" "}
            {(ps2.blocked_tools ?? []).map((tool, i) => (
              <span key={tool}>
                {i ? ", " : ""}
                <code>{tool}</code>
              </span>
            ))}
            . Their registered implementation{" "}
            <code>{Array.from(new Set(Object.values(ps2.registry ?? {}))).join(", ")}</code> goes to
            PatchProof.
          </span>
        ) : (
          <span>
            <strong>Bridge not triggered.</strong> {ps2.reason}
          </span>
        )}
      </div>

      <div id="doclab-fix" className="ws-anchor" />
      <StageLabel layer="Root-cause fix" title="PatchProof" detail="Find → prove with an exploit → patch → verify" muted={!ps2.triggered} />

      {ps2.triggered ? (
        (ps2.targets ?? []).map((target) => <CodeTargetView key={target.target} target={target} />)
      ) : (
        <Card>
          <EmptyState
            icon={Bug}
            title={blocked.length ? "No governed implementation to scan" : "Nothing to fix"}
            description={ps2.reason ?? "No block, no code scan."}
          />
        </Card>
      )}
    </>
  );
}

function DocumentScan({ verdicts }: { verdicts: DetectorVerdict[] }) {
  if (!verdicts.length) return null;
  const keyword = verdicts.find((v) => v.detector === "heuristic");
  const llmCaught = verdicts.some((v) => v.detector.startsWith("llm") && v.threat);
  return (
    <div className="ws-doclab-scan">
      <p className="ws-label">Whole-document verdicts</p>
      <ul>
        {verdicts.map((v) => (
          <li key={v.detector}>
            <code>{v.detector}</code>
            {v.error ? (
              <span className="ws-badge is-hold">unavailable</span>
            ) : (
              <span className={cn("ws-badge", v.threat ? "is-deny" : "is-allow")}>
                {v.threat ? "threat" : "clean"} · {v.score.toFixed(2)}
              </span>
            )}
            <span className="ws-doclab-scan-signal">{v.error ?? v.signals[0] ?? "no signal"}</span>
          </li>
        ))}
      </ul>
      {llmCaught && keyword && !keyword.threat ? (
        <p className="ws-doclab-scan-callout">
          The keyword detector found nothing here. The LLM layer read the intent and flagged it.
        </p>
      ) : null}
    </div>
  );
}

/* ------------------------------------------------------------ summary */

function VerdictHero({ result, seconds }: { result: DocumentAnalysis; seconds: number | null }) {
  const { ps1, ps2 } = result;
  const hidden = ps1.ingestion?.hidden_segments.length ?? 0;
  const decoded = ps1.ingestion?.decoded_segments.length ?? 0;
  const flagged = ps1.detection.flagged_total;
  const threatFound = flagged > 0 || hidden + decoded > 0 || ps1.detection.document_scan.some((v) => v.threat);
  const injected = ps1.decisions.filter((d) => d.origin === "document_instruction");
  const stopped = ps1.decisions.filter((d) => d.would_block);
  const denied = ps1.summary.deny ?? 0;
  const held = ps1.summary.require_approval ?? 0;
  const fixed = (ps2.targets ?? []).reduce((sum, t) => sum + t.fixed, 0);
  const attack = threatFound || injected.length > 0;

  const steps = [
    {
      label: "Hidden instruction",
      value: attack ? `${injected.length || flagged} found` : "none",
      detail: attack
        ? [
            hidden ? `${hidden} hidden segment${hidden === 1 ? "" : "s"}` : null,
            flagged ? `${flagged} flagged sentence${flagged === 1 ? "" : "s"}` : null,
            injected.length ? `${injected.length} action${injected.length === 1 ? "" : "s"} attempted` : null,
          ]
            .filter(Boolean)
            .join(" · ")
        : "nothing in the document tried to steer the agent",
      tone: attack ? "is-threat" : "is-clean",
      href: "#doclab-document",
    },
    {
      label: "Actions",
      value: stopped.length ? `${stopped.length} stopped` : "allowed",
      detail: stopped.length
        ? `${denied} denied · ${held} held for a human · before any tool ran`
        : "the agent read the document normally",
      tone: stopped.length ? "is-stopped" : "is-clean",
      href: "#doclab-runtime",
    },
    {
      label: "Code",
      value: ps2.triggered ? `${fixed} fixed` : "not needed",
      detail: ps2.triggered
        ? "the attacked tool's weaknesses were exploit-proven, patched and re-verified"
        : "no governed tool was attacked, so no code scan ran",
      tone: ps2.triggered ? "is-fixed" : "is-idle",
      href: "#doclab-fix",
    },
  ];

  return (
    <section className={cn("ws-doclab-verdict", attack ? "is-attack" : "is-clean")} aria-live="polite">
      <div className="ws-doclab-verdict-head">
        <span className="ws-doclab-verdict-icon">
          {attack ? <ShieldCheck className="h-5 w-5" /> : <CheckCircle2 className="h-5 w-5" />}
        </span>
        <div>
          <strong>
            {attack
              ? stopped.length
                ? "Attack stopped before any tool ran."
                : "Suspicious content found and contained."
              : "No attack: the document was read normally."}
          </strong>
          <span>
            {result.document.filename}
            {seconds != null ? ` · analyzed in ${seconds.toFixed(1)}s` : ""}
            {ps1.enforced ? "" : " · enforcement OFF: verdicts recorded, not enforced"}
          </span>
        </div>
      </div>
      <ol className="ws-doclab-verdict-steps">
        {steps.map((step, index) => (
          <li key={step.label} className={step.tone}>
            <a href={step.href}>
              <span className="ws-doclab-verdict-n">{index + 1}</span>
              <span className="ws-doclab-verdict-label">{step.label}</span>
              <strong>{step.value}</strong>
              <span className="ws-doclab-verdict-detail">{step.detail}</span>
            </a>
          </li>
        ))}
      </ol>
    </section>
  );
}

/** Mark each flagged phrase inside the text, tolerant of whitespace differences. */
function highlight(text: string, phrases: string[]) {
  const ranges: Array<[number, number]> = [];
  for (const phrase of phrases.slice(0, 16)) {
    const words = phrase.split(/\s+/).filter(Boolean).slice(0, 40);
    if (words.length < 3) continue;
    const pattern = new RegExp(words.map((w) => w.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("\\s+"));
    const match = pattern.exec(text);
    if (match) ranges.push([match.index, match.index + match[0].length]);
  }
  ranges.sort((a, b) => a[0] - b[0]);
  const parts: Array<{ text: string; marked: boolean }> = [];
  let cursor = 0;
  for (const [start, end] of ranges) {
    if (start < cursor) continue;
    if (start > cursor) parts.push({ text: text.slice(cursor, start), marked: false });
    parts.push({ text: text.slice(start, end), marked: true });
    cursor = end;
  }
  if (cursor < text.length) parts.push({ text: text.slice(cursor), marked: false });
  return parts;
}

function DocumentView({ result }: { result: DocumentAnalysis }) {
  const { document: doc, ps1 } = result;
  const ing = ps1.ingestion;
  const phrases = ps1.detection.flagged.map((f) => f.text);
  const parts = highlight(doc.excerpt, phrases);
  const concealed = [...(ing?.hidden_segments ?? []), ...(ing?.decoded_segments ?? [])];
  return (
    <Card id="doclab-document" className="ws-anchor">
      <CardHead
        title="What's inside the document"
        icon={FileSearch}
        subtitle="What a person sees, what was hidden in it, and what the agent is actually given"
      />
      <CardBody>
        <div className="ws-doclab-docview">
          <div>
            <p className="ws-label">The document {doc.kind === "pdf" ? "(text layer, including white text)" : ""}</p>
            <pre className="ws-doclab-doctext">
              {parts.map((part, index) =>
                part.marked ? (
                  <mark key={index} title="Flagged as an injected instruction">
                    {part.text}
                  </mark>
                ) : (
                  <span key={index}>{part.text}</span>
                ),
              )}
              {doc.chars > doc.excerpt.length ? "\n…" : ""}
            </pre>
            {parts.some((part) => part.marked) ? (
              <p className="ws-hint">
                <mark className="ws-doclab-legend-mark">Highlighted</mark> sentences read as instructions to the agent.
              </p>
            ) : null}
          </div>
          <div>
            <p className="ws-label">Hidden or encoded content</p>
            {concealed.length ? (
              <ul className="ws-doclab-hidden">
                {concealed.map((segment, index) => (
                  <li key={index}>
                    <span className="ws-badge is-deny">{segment.reason}</span>
                    <p>{segment.text}</p>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="ws-doclab-none">
                {ing
                  ? "No hidden markup, invisible characters or encoded payloads found."
                  : "Ingestion inspection is not available on this gateway."}
              </p>
            )}
            {doc.kind === "pdf" ? (
              <p className="ws-hint">
                PDF colour isn&apos;t preserved in text extraction: white-on-white text appears in the document
                text on the left, where its sentences are flagged.
              </p>
            ) : null}
          </div>
          <div>
            <p className="ws-label">What the agent is given</p>
            {ing ? (
              <>
                <pre className="ws-doclab-agenttext">{ing.agent_text_preview}</pre>
                <p className="ws-hint">
                  Hidden content is stripped and the rest is wrapped as untrusted data, so the model is told to
                  treat it as information, not instructions.
                </p>
              </>
            ) : (
              <p className="ws-doclab-none">Not available on this gateway.</p>
            )}
          </div>
        </div>
      </CardBody>
    </Card>
  );
}

function StageLabel({
  layer,
  title,
  detail,
  muted = false,
}: {
  layer: string;
  title: string;
  detail: string;
  muted?: boolean;
}) {
  return (
    <div className={cn("ws-doclab-stage", muted && "is-muted")}>
      <span className="ws-doclab-stage-chip">{layer}</span>
      <strong>{title}</strong>
      <span>{detail}</span>
    </div>
  );
}

function DecisionRow({ decision, index }: { decision: DocumentDecision; index: number }) {
  return (
    <li className={cn("ws-doclab-decision", `is-${decision.decision}`)}>
      <div className="ws-doclab-decision-head">
        <span className="ws-doclab-step">{String(index + 1).padStart(2, "0")}</span>
        <code className="ws-doclab-tool">{decision.tool}</code>
        <span className={cn("ws-badge", decision.origin === "user_task" ? "is-allow" : "is-hold")}>
          {decision.origin === "user_task" ? "User task" : "From the document"}
        </span>
        <span className="ws-doclab-spacer" />
        <DecisionBadge decision={decision.decision} />
      </div>
      <p className="ws-doclab-narration">{decision.narration}</p>
      {decision.quote ? <blockquote className="ws-doclab-quote">“{decision.quote}”</blockquote> : null}
      <p className="ws-doclab-args">
        <span>source</span> {decision.source} <span>args</span> {JSON.stringify(decision.arguments)}
      </p>
      <ReasonList reasons={decision.reasons} />
      <Link href={`/workspace/audit?call=${encodeURIComponent(decision.call_id)}`} className="ws-doclab-audit">
        <Fingerprint className="h-3.5 w-3.5" /> {decision.call_id} · open in audit trail
      </Link>
    </li>
  );
}

function CodeTargetView({ target }: { target: CodeTarget }) {
  return (
    <Card>
      <CardHead
        title={<span className="ws-mono">{target.target}</span>}
        icon={Wrench}
        subtitle={`sha256 ${target.sha256.slice(0, 12)}… · engine ${target.engine} · ${
          target.cached ? "verified result reused (fixture unchanged)" : `computed in ${(target.duration_ms / 1000).toFixed(1)}s`
        }`}
      />
      <CardBody>
        <div className="ws-doclab-funnel">
          <FunnelStep value={target.raw_alerts} label="scanner alerts" />
          <FunnelStep value={target.confirmed} label="proven by a real exploit" tone="deny" />
          <FunnelStep value={target.fixed} label="patched & verified" tone="allow" />
          <FunnelStep value={target.false_positives_dropped} label="unproven alerts dropped" tone="muted" />
          <div className="ws-doclab-precision">
            precision {Math.round(target.precision_before * 100)}% → {Math.round(target.precision_after * 100)}%
          </div>
        </div>
        <div className="ws-doclab-issues">
          {target.issues.map((issue, index) => (
            <IssueView key={`${issue.cwe}-${issue.location}`} issue={issue} defaultOpen={index === 0} />
          ))}
        </div>
      </CardBody>
    </Card>
  );
}

function FunnelStep({ value, label, tone }: { value: number; label: string; tone?: "deny" | "allow" | "muted" }) {
  return (
    <div className={cn("ws-doclab-funnel-step", tone && `is-${tone}`)}>
      <strong>{formatNumber(value)}</strong>
      <span>{label}</span>
    </div>
  );
}

function IssueView({ issue, defaultOpen }: { issue: CodeIssue; defaultOpen: boolean }) {
  return (
    <details className="ws-doclab-issue" open={defaultOpen}>
      <summary>
        <SeverityBadge severity={issue.severity} />
        <code>{issue.cwe}</code>
        <span className="ws-doclab-issue-title">{issue.title}</span>
        <span className="ws-doclab-issue-loc ws-mono">{issue.location}</span>
      </summary>
      <div className="ws-doclab-issue-body">
        <section>
          <h4>Where</h4>
          <p className="ws-mono">
            {issue.location}
            {issue.route ? ` · ${issue.route}` : ""}
            {issue.param ? ` · param ${issue.param}` : ""}
          </p>
          <pre className="ws-doclab-snippet">{issue.snippet}</pre>
          <h4>Why it matters</h4>
          <p>{issue.severity_rationale}</p>
        </section>
        <section>
          <h4>Proof: the exploit before the patch</h4>
          <p className="ws-doclab-exploit">{issue.exploit ?? "—"}</p>
          <h4>Fix</h4>
          <p>{issue.patch_rationale ?? "—"}</p>
          <Diff text={issue.diff} />
        </section>
        <ul className="ws-doclab-checks">
          <Check ok={issue.exploit_blocked} label="Exploit blocked after the patch" />
          <Check ok={issue.regression_passed} label={`Regression suite green (${issue.regression_checks} checks)`} />
          <Check
            ok={issue.variants_total > 0 && issue.variants_blocked === issue.variants_total}
            label={`Payload variants blocked ${issue.variants_blocked}/${issue.variants_total}`}
          />
          <Check ok={issue.accepted} label={`Minimal patch accepted (+${issue.lines_added} −${issue.lines_removed} lines)`} />
        </ul>
      </div>
    </details>
  );
}

function Check({ ok, label }: { ok: boolean; label: string }) {
  return (
    <li className={cn(ok ? "is-ok" : "is-fail")}>
      {ok ? <CheckCircle2 className="h-3.5 w-3.5" /> : <XCircle className="h-3.5 w-3.5" />} {label}
    </li>
  );
}

function Diff({ text }: { text: string }) {
  if (!text) return <p className="ws-hint">No diff recorded.</p>;
  return (
    <pre className="ws-doclab-diff" aria-label="Patch diff">
      {text.split("\n").map((line, index) => (
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
  );
}
