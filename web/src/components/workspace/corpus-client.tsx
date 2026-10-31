"use client";

import {
  AlertTriangle,
  Database,
  FileText,
  FilterX,
  Lock,
  RefreshCw,
  RotateCcw,
  Search,
  ShieldAlert,
  ShieldCheck,
  Tags,
} from "lucide-react";
import { useMemo, useState } from "react";
import { apiPost } from "@/lib/api/client";
import { toApiFailure, type ApiFailure } from "@/lib/api/errors";
import { formatNumber, titleCase } from "@/lib/api/format";
import type { CorpusDoc, CorpusResponse, ResetResponse } from "@/lib/api/types";
import { useLiveData } from "@/lib/hooks/use-live-data";
import { cn } from "@/lib/utils";
import { useSession } from "./session-context";
import { ConfirmDialog } from "@/components/workspace/confirm-dialog";
import { CopyButton } from "@/components/workspace/copy-button";
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
  StatCard,
  StatusBadge,
  SuccessNote,
} from "@/components/workspace/ui";

export function CorpusClient() {
  const { role, requireAdmin, noteUnauthorized } = useSession();
  const isAdmin = role === "admin";
  const [search, setSearch] = useState("");
  const [lang, setLang] = useState("all");
  const [label, setLabel] = useState("all");
  const [channel, setChannel] = useState("all");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [confirmReset, setConfirmReset] = useState(false);
  const [resetting, setResetting] = useState(false);
  const [failure, setFailure] = useState<ApiFailure | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const corpus = useLiveData<CorpusResponse>("/v1/corpus", { intervalMs: 60_000 });

  const docs = useMemo(() => corpus.data?.docs ?? [], [corpus.data]);
  const languages = useMemo(
    () => Array.from(new Set(docs.map((doc) => doc.lang).filter(Boolean))).sort() as string[],
    [docs],
  );
  const labels = useMemo(
    () => Array.from(new Set(docs.map((doc) => doc.label).filter(Boolean))).sort() as string[],
    [docs],
  );
  const channels = useMemo(
    () => Array.from(new Set(docs.map((doc) => doc.channel).filter(Boolean))).sort() as string[],
    [docs],
  );

  const filtered = useMemo(() => {
    const term = search.trim().toLowerCase();
    return docs.filter((doc) => {
      if (lang !== "all" && doc.lang !== lang) return false;
      if (label !== "all" && doc.label !== label) return false;
      if (channel !== "all" && doc.channel !== channel) return false;
      if (!term) return true;
      return [doc.id, doc.text, doc.lang, doc.label, doc.channel]
        .join(" ")
        .toLowerCase()
        .includes(term);
    });
  }, [channel, docs, label, lang, search]);

  const selected =
    docs.find((doc) => doc.id === selectedId) ?? filtered[0] ?? null;

  const benign = docs.filter((doc) => doc.label === "benign").length;
  const suspicious = docs.filter((doc) => doc.label === "suspicious").length;
  const activeFilters =
    search.trim().length > 0 || lang !== "all" || label !== "all" || channel !== "all";

  const clearFilters = () => {
    setSearch("");
    setLang("all");
    setLabel("all");
    setChannel("all");
  };

  const reset = async () => {
    setResetting(true);
    setFailure(null);
    setSuccess(null);
    try {
      const result = await apiPost<ResetResponse>("/v1/admin/reset");
      setSuccess(
        `Corpus re-ingested: ${result.corpus_docs} document${result.corpus_docs === 1 ? "" : "s"} loaded. Audit history was not deleted.`,
      );
      setConfirmReset(false);
      setSelectedId(null);
      await corpus.refresh();
    } catch (error) {
      noteUnauthorized(error);
      setFailure(toApiFailure(error));
      setConfirmReset(false);
    } finally {
      setResetting(false);
    }
  };

  const requestReset = () => {
    setFailure(null);
    setSuccess(null);
    // Operators get the admin sign-in dialog; after a successful sign-in the
    // confirm dialog opens automatically via the pending action.
    requireAdmin(() => setConfirmReset(true));
  };

  return (
    <div className="ws-stack">
      <PageHeader
        eyebrow="RAG corpus"
        title={
          <>
            Retrieved, <em>never trusted.</em>
          </>
        }
        description="Every record in the retrieval corpus is tagged UNTRUSTED at ingest. Retrieval never confers trust. Explore the exact documents an agent may read, their language, channel and benign/suspicious ingest label."
        actions={
          <>
            <button
              type="button"
              className="ws-btn is-sm"
              onClick={() => void corpus.refresh()}
              disabled={corpus.isRefreshing}
            >
              <RefreshCw
                className={cn("h-3.5 w-3.5", corpus.isRefreshing && "animate-spin")}
              />
              {corpus.isRefreshing ? "Refreshing" : "Refresh"}
            </button>
            <button
              type="button"
              className="ws-btn is-danger is-sm"
              onClick={requestReset}
              disabled={resetting || !corpus.data?.available}
            >
              {isAdmin ? (
                <RotateCcw className="h-3.5 w-3.5" />
              ) : (
                <Lock className="h-3.5 w-3.5" />
              )}{" "}
              {isAdmin ? "Re-ingest corpus" : "Admin only · Re-ingest"}
            </button>
          </>
        }
      />

      {corpus.failure && corpus.data ? (
        <Banner tone="warn" icon={AlertTriangle}>
          <strong>Live updates interrupted.</strong> Showing the last successful corpus
          snapshot. {corpus.failure.message}
        </Banner>
      ) : null}
      {failure ? <ErrorState failure={failure} compact /> : null}
      {success ? <SuccessNote>{success}</SuccessNote> : null}

      <Banner tone="purple" icon={ShieldAlert}>
        <strong>Trust is not a document property.</strong> The corpus carries an ingest
        label for testing, but the gateway still treats every retrieved record as
        UNTRUSTED. A document labelled benign is not automatically safe; a document
        labelled suspicious is not automatically blocked. The policy and detectors
        decide per tool call.
      </Banner>

      <div className="ws-grid ws-grid-4">
        <StatCard
          label="Corpus documents"
          value={corpus.data ? formatNumber(corpus.data.count) : "—"}
          meta={corpus.data?.available ? "Loaded from the RAG store" : "Corpus unavailable"}
          icon={Database}
        />
        <StatCard
          label="Untrusted records"
          value={corpus.data ? formatNumber(corpus.data.count) : "—"}
          meta="Every record, by construction"
          icon={ShieldAlert}
        />
        <StatCard
          label="Ingest label · benign"
          value={corpus.data ? formatNumber(benign) : "—"}
          meta="Testing label only · not a trust grant"
          icon={ShieldCheck}
          tone="lime"
        />
        <StatCard
          label="Ingest label · suspicious"
          value={corpus.data ? formatNumber(suspicious) : "—"}
          meta="Testing label only · not a detector verdict"
          icon={Tags}
          tone="purple"
        />
      </div>

      <div className="ws-grid ws-grid-sidebar">
        <Card>
          <CardHead
            title="Documents"
            subtitle="GET /v1/corpus · all records tagged UNTRUSTED"
            icon={Database}
            actions={
              corpus.lastUpdated ? (
                <LiveMeta
                  lastUpdated={corpus.lastUpdated}
                  isRefreshing={corpus.isRefreshing}
                  isStale={corpus.isStale}
                  intervalLabel="60s"
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
                  placeholder="Document ID or text"
                  aria-label="Search corpus documents"
                />
              </span>
            </label>
            <label className="ws-field">
              <span className="ws-label">Language</span>
              <select
                className="ws-select"
                value={lang}
                onChange={(event) => setLang(event.target.value)}
              >
                <option value="all">All languages</option>
                {languages.map((value) => (
                  <option key={value} value={value}>
                    {value}
                  </option>
                ))}
              </select>
            </label>
            <label className="ws-field">
              <span className="ws-label">Label</span>
              <select
                className="ws-select"
                value={label}
                onChange={(event) => setLabel(event.target.value)}
              >
                <option value="all">All labels</option>
                {labels.map((value) => (
                  <option key={value} value={value}>
                    {titleCase(value)}
                  </option>
                ))}
              </select>
            </label>
            <label className="ws-field">
              <span className="ws-label">Channel</span>
              <select
                className="ws-select"
                value={channel}
                onChange={(event) => setChannel(event.target.value)}
              >
                <option value="all">All channels</option>
                {channels.map((value) => (
                  <option key={value} value={value}>
                    {titleCase(value)}
                  </option>
                ))}
              </select>
            </label>
            <span className="ws-count-pill">
              {filtered.length} / {docs.length}
            </span>
            {activeFilters ? (
              <button type="button" className="ws-btn is-xs is-ghost" onClick={clearFilters}>
                <FilterX className="h-3 w-3" /> Clear
              </button>
            ) : null}
          </div>

          {corpus.isLoading ? (
            <CardBody>
              <LoadingState rows={3} />
            </CardBody>
          ) : corpus.failure && !corpus.data ? (
            <CardBody>
              <ErrorState failure={corpus.failure} onRetry={() => void corpus.refresh()} />
            </CardBody>
          ) : filtered.length ? (
            <CardBody>
              <div className="ws-grid ws-grid-2">
                {filtered.map((doc) => (
                  <button
                    key={doc.id}
                    type="button"
                    className={cn(
                      "ws-doc",
                      selected?.id === doc.id && "is-selected",
                    )}
                    onClick={() => setSelectedId(doc.id)}
                    aria-pressed={selected?.id === doc.id}
                  >
                    <div className="ws-doc-head">
                      <span className="ws-doc-id">{doc.id}</span>
                      <span className="ws-badge is-deny">untrusted</span>
                      {doc.label ? (
                        <span
                          className={cn(
                            "ws-badge",
                            doc.label === "suspicious" ? "is-hold" : "is-neutral",
                          )}
                        >
                          {doc.label}
                        </span>
                      ) : null}
                    </div>
                    <p className="ws-doc-text line-clamp-3">{doc.text}</p>
                    <div className="ws-doc-meta">
                      <span>{doc.lang ?? "no lang"}</span>
                      <span>{doc.channel ?? "no channel"}</span>
                      <span>{formatNumber(doc.chars)} chars</span>
                    </div>
                  </button>
                ))}
              </div>
            </CardBody>
          ) : docs.length ? (
            <EmptyState
              title="No documents match these filters."
              description="Clear the filters to see the full corpus."
              icon={FilterX}
              action={
                <button type="button" className="ws-btn is-sm" onClick={clearFilters}>
                  Clear filters
                </button>
              }
            />
          ) : (
            <EmptyState
              title="Corpus is empty or unavailable."
              description="The gateway reported no documents. Use Re-ingest corpus to load the packaged corpus, or check the RAG store on the gateway host."
              icon={Database}
            />
          )}
        </Card>

        <div className="ws-detail">
          <Card>
            <CardHead
              title="Document inspector"
              subtitle="Exact text · UNTRUSTED at ingest"
              icon={FileText}
              actions={
                selected ? (
                  <CopyButton value={JSON.stringify(selected, null, 2)} label="Copy JSON" />
                ) : null
              }
            />
            <CardBody>
              {selected ? <DocDetail doc={selected} /> : (
                <EmptyState
                  title="Select a document."
                  description="Choose a corpus record to inspect its exact text, metadata and trust label."
                  icon={FileText}
                />
              )}
            </CardBody>
          </Card>
        </div>
      </div>

      <Banner tone="purple" icon={ShieldCheck}>
        <strong>No upload or edit endpoint.</strong> This build exposes corpus reads and
        a confirmed admin re-ingest only. It does not accept documents from the browser,
        and it does not change audit history. {corpus.data?.note ?? ""}
      </Banner>

      <ConfirmDialog
        open={confirmReset}
        title="Re-ingest the RAG corpus?"
        description={
          <>
            <p>
              This calls{" "}
              <code className="ws-mono">POST /v1/admin/reset</code>. It reloads the
              packaged corpus into the RAG store.
            </p>
            <p className="mt-2">
              Audit history is retained. The global enforcement switch is not changed.
              Existing retrieved documents are replaced by the packaged corpus.
            </p>
          </>
        }
        confirmLabel="Re-ingest"
        tone="danger"
        pending={resetting}
        onConfirm={() => void reset()}
        onCancel={() => {
          if (!resetting) setConfirmReset(false);
        }}
      />
    </div>
  );
}

function DocDetail({ doc }: { doc: CorpusDoc }) {
  return (
    <div className="ws-stack">
      <div className="ws-wrap">
        <span className="ws-badge is-deny">untrusted</span>
        {doc.label ? (
          <span
            className={cn(
              "ws-badge",
              doc.label === "suspicious" ? "is-hold" : "is-neutral",
            )}
          >
            ingest label: {doc.label}
          </span>
        ) : null}
      </div>
      <div className="ws-doc-id ws-fs-body">{doc.id}</div>
      <KeyValue
        items={[
          { label: "Language", value: doc.lang ?? "not recorded" },
          { label: "Channel", value: doc.channel ?? "not recorded" },
          { label: "Label", value: doc.label ?? "not recorded" },
          { label: "Characters", value: formatNumber(doc.chars) },
          { label: "Trust", value: <StatusBadge tone="error">UNTRUSTED</StatusBadge> },
        ]}
      />
      <div>
        <span className="ws-label">Exact text</span>
        <pre className="ws-code mt-1.5 whitespace-pre-wrap">{doc.text}</pre>
      </div>
      <div className="ws-banner is-warn">
        <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0" />
        <div>
          The ingest label is test-fixture metadata. It does not grant trust, and it is
          not a live detector verdict. Only the policy engine and detectors decide a
          tool call.
        </div>
      </div>
    </div>
  );
}
