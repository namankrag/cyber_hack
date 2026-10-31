/**
 * Typed response models for the AgentShield gateway.
 *
 * These mirror the response shapes produced by agentshield/gateway/app.py,
 * insights.py, redteam.py and evidence.py. Optional / nullable fields are
 * modelled explicitly because the gateway deliberately reports what it does
 * not know rather than inventing a value.
 */

export type DecisionValue = "allow" | "deny" | "require_approval";
export type SourceValue = "user" | "system" | "trusted_tool" | "untrusted";

export interface PolicyReason {
  rule: string;
  decision: DecisionValue;
  detail: string;
}

export interface DetectionResult {
  detector: string;
  score: number;
  is_threat: boolean;
  signals: string[];
  error?: string | null;
}

export interface AuditEntry {
  ts: number | string;
  call_id: string;
  tool: string;
  arguments: Record<string, unknown>;
  source: string;
  decision: string;
  fail_closed: boolean;
  reasons: PolicyReason[];
  detections: DetectionResult[];
  metadata: Record<string, unknown>;
  approval?: "approve" | "deny" | "consumed";
  approval_of?: string;
  args_hash?: string;
  consumed_by?: string;
}

export interface HealthResponse {
  status: string;
  detectors: string[];
  auth_required: boolean;
}

export interface ReadyResponse {
  ready: boolean;
}

export interface EnforceResponse {
  enforced: boolean;
}

export interface AdminEnforceResponse {
  enforced: boolean;
}

export interface ResetResponse {
  reset: boolean;
  corpus_docs: number;
}

export interface CheckRequest {
  tool_name: string;
  arguments: Record<string, unknown>;
  source?: string;
  context?: string;
  metadata?: Record<string, unknown>;
}

export interface CheckResponse {
  call_id: string;
  decision: DecisionValue;
  fail_closed: boolean;
  resolved_source: string;
  reasons: PolicyReason[];
  headline: string;
}

export interface MetricsSample {
  entries_read: number;
  events_in_window: number;
  limit: number;
  truncated: boolean;
}

export interface MetricsTotals {
  evaluated: number;
  allowed: number;
  blocked: number;
  held: number;
  pending_approvals: number;
  threats: number;
  detector_errors: number;
}

export interface MetricsSeriesPoint {
  ts: number;
  total: number;
  allow: number;
  deny: number;
  require_approval: number;
  threats: number;
}

export interface MetricsToolRow {
  tool: string;
  total: number;
  allow: number;
  deny: number;
  require_approval: number;
  threats: number;
}

export interface MetricsSourceRow {
  source: string;
  count: number;
}

export interface MetricsDetectorRow {
  detector: string;
  runs: number;
  threats: number;
  errors: number;
  avg_score: number | null;
}

export interface MetricsResponse {
  generated_at: number;
  window: string;
  sample: MetricsSample;
  totals: MetricsTotals;
  previous_totals: {
    evaluated: number;
    allowed: number;
    blocked: number;
    threats: number;
  };
  deltas: Record<string, number | null>;
  series: MetricsSeriesPoint[];
  decision_distribution: Array<{ decision: string; count: number }>;
  top_tools: MetricsToolRow[];
  sources: MetricsSourceRow[];
  detectors: MetricsDetectorRow[];
  span: {
    first: string | null;
    last: string | null;
    seconds: number | null;
  };
  notes: Record<string, string>;
}

export interface ThreatEvent {
  threat_id: string;
  call_id: string;
  timestamp: string | null;
  epoch: number | null;
  tool: string;
  source: string;
  decision: string;
  detector: string;
  score: number;
  signals: string[];
  category: string;
  category_label: string;
  category_inferred: boolean;
  severity: "high" | "medium" | "low";
  severity_label: string;
  severity_basis: string;
  arguments: Record<string, unknown>;
  reasons: PolicyReason[];
  fail_closed: boolean;
  audit_entry: AuditEntry;
  context_available: boolean;
  context_note: string;
}

export interface ThreatsResponse {
  generated_at: number;
  total: number;
  severity: { high: number; medium: number; low: number };
  categories: Array<{ key: string; label: string; count: number }>;
  events: ThreatEvent[];
  sample: MetricsSample;
  classification_note: string;
}

export interface ApprovalsSummary {
  pending: number;
  approved: number;
  rejected: number;
  consumed: number;
  expired: number | null;
}

export interface ApprovalCapabilities {
  decide: boolean;
  single_use: boolean;
  args_hash_bound: boolean;
  expiry: boolean;
}

export interface ApprovalsResponse {
  generated_at: number;
  summary: ApprovalsSummary;
  capabilities: ApprovalCapabilities;
  pending: AuditEntry[];
  recent: AuditEntry[];
  sample: MetricsSample;
  notes: Record<string, string>;
}

export interface ApprovalDecisionResponse {
  entry: AuditEntry;
  summary: ApprovalsSummary;
}

export interface PolicyDefaults {
  unknown_tool: DecisionValue;
  on_detector_threat_high_sensitivity: DecisionValue;
  on_detector_threat_low_sensitivity: DecisionValue;
  on_untrusted_high_sensitivity: DecisionValue;
  on_untrusted_low_sensitivity: DecisionValue;
  fail_closed_on_detector_error: boolean;
  detector_error_decision: DecisionValue;
}

export interface PolicyTool {
  name: string;
  sensitivity: "low" | "high";
  allow: boolean;
  require_approval: boolean;
  allow_sources: string[];
  on_disallowed_source: DecisionValue;
  decision_requirement: string;
}

export interface EvaluationStage {
  step: number;
  rule: string;
  label: string;
  description: string;
}

export interface PolicyResponse {
  generated_at: number;
  name: string;
  path: string;
  version: number;
  digest: string | null;
  expected_digest: string | null;
  digest_pinned: boolean;
  integrity_verified: boolean | null;
  updated_at: string | null;
  loaded_at: string | null;
  defaults: PolicyDefaults;
  tools: PolicyTool[];
  tool_count: number;
  yaml: string;
  read_only: boolean;
  write_api: boolean;
  evaluation_order: EvaluationStage[];
  notes: Record<string, string>;
}

export interface ToolActivity {
  calls: number;
  allow: number;
  deny: number;
  require_approval: number;
  last_decision: string | null;
  last_seen: string | null;
  sources: string[];
}

export interface ToolView {
  name: string;
  sensitivity: string;
  enabled: boolean | null;
  require_approval: boolean | null;
  allow_sources: string[];
  on_disallowed_source: string | null;
  decision_requirement: string;
  activity: ToolActivity;
}

export interface ToolsResponse {
  generated_at: number;
  tools: ToolView[];
  policy_tool_count: number;
  activity_window: MetricsSample;
  notes: Record<string, string>;
}

export interface AgentSession {
  agent: string;
  session_id: string;
  calls: number;
  allow: number;
  deny: number;
  require_approval: number;
  first_seen: string | null;
  last_seen: string | null;
  tools: string[];
  sources: string[];
}

export interface AgentsResponse {
  generated_at: number;
  sessions: AgentSession[];
  count: number;
  sample: MetricsSample;
  notes: Record<string, string>;
}

export interface CorpusDoc {
  id: string;
  lang: string | null;
  label: string | null;
  channel: string | null;
  trust: "UNTRUSTED";
  text: string;
  chars: number;
}

export interface CorpusResponse {
  generated_at: number;
  count: number;
  docs: CorpusDoc[];
  available: boolean;
  note: string;
}

export interface RedteamScenario {
  id: string;
  title: string;
  description: string;
  attack_type: string;
  source: string;
  tool_name: string;
  arguments: Record<string, unknown>;
  context: string;
  doc_id: string | null;
  expected_decision: DecisionValue;
  tags: string[];
}

export interface RedteamScenariosResponse {
  generated_at: number;
  scenarios: RedteamScenario[];
  enforcement_note: string;
}

export interface RedteamStage {
  key: string;
  label: string;
  status: "complete" | "warning" | string;
  detail: string;
  blocked?: boolean;
}

export interface RedteamRunSide {
  enforced: boolean;
  decision: string;
  fail_closed: boolean;
  call_id: string;
  headline: string;
  reasons: PolicyReason[];
  detections: DetectionResult[];
  duration_ms: number;
  audit_record: AuditEntry | null;
  stages: RedteamStage[];
}

export interface RedteamRunResponse {
  run_id: string;
  generated_at: number;
  scenario_id: string | null;
  request: {
    tool_name: string;
    arguments: Record<string, unknown>;
    source: string;
    context: string;
    metadata: Record<string, unknown>;
  };
  on: RedteamRunSide;
  off: RedteamRunSide;
  comparison: {
    gate_off_permitted: boolean;
    gate_on_blocked: boolean;
    verdict_changed: boolean;
  };
  audit_path: string;
  global_enforcement_unchanged: boolean;
  notes: Record<string, string>;
}

export interface RedteamHistoryResponse {
  generated_at: number;
  path: string;
  entries: AuditEntry[];
  available: boolean;
}

export interface EvidenceResponse {
  health: HealthResponse;
  enforced: boolean;
  manifest_enforced?: boolean | null;
  provenance_dev_mode: boolean;
  entries: AuditEntry[];
}

export interface EvidenceArtifact {
  available: boolean;
  path: string;
  updated_at?: string;
  bytes?: number;
}

export interface EvidenceReport {
  id: string;
  title: string;
  category: string;
  status: string;
  status_label: string;
  value: string;
  detail: string;
  source: string;
  recorded_commit: string | null;
  recorded_date: string | null;
  live: boolean;
  artifacts: EvidenceArtifact[];
  note: string;
  command: string;
  health?: HealthResponse;
  enforced?: boolean;
  provenance_dev_mode?: boolean;
  digest?: string | null;
  integrity_verified?: boolean | null;
  semgrep?: {
    available: boolean;
    version?: string;
    results?: number;
    errors?: number;
    paths_scanned?: number;
    path?: string;
  };
  ledger?: {
    available: boolean;
    rows: number;
    by_status: Record<string, number>;
    by_severity: Record<string, number>;
    path?: string;
  };
  corpus_docs?: number;
}

export interface EvidenceReportsResponse {
  generated_at: number;
  repo: {
    commit: string | null;
    commit_date: string | null;
    branch: string | null;
  };
  reports: EvidenceReport[];
  baseline: {
    pytest: string;
    semgrep_rules: number;
    semgrep_findings: number;
    rag_beats: number;
    corpus_docs: number;
    red_team_ledger_rows: number;
  };
  notes: Record<string, string>;
}

export interface AuditResponse {
  entries: AuditEntry[];
}

/* -------------------------------------------------------------------------
   Document Lab (POST /v1/document/analyze): one document through PS-1
   (runtime decisions) and, when a governed tool is blocked, PS-2 (code).
   ------------------------------------------------------------------------- */

export interface DocumentSample {
  id: string;
  title: string;
  filename: string;
}

export interface DocumentSamplesResponse {
  samples: DocumentSample[];
  max_file_bytes: number;
}

export interface DocumentFlaggedSentence {
  text: string;
  score: number;
  threat: boolean;
  signals: string[];
}

export interface DetectorVerdict {
  detector: string;
  score: number;
  threat: boolean;
  signals: string[];
  error: string | null;
}

export interface DocumentDecision {
  call_id: string;
  tool: string;
  arguments: Record<string, unknown>;
  source: string;
  origin: "user_task" | "document_instruction";
  quote: string | null;
  narration: string;
  decision: DecisionValue;
  would_block: boolean;
  fail_closed: boolean;
  reasons: PolicyReason[];
  detections: DetectorVerdict[];
  headline: string;
}

export interface CodeIssue {
  cwe: string;
  title: string;
  severity: string;
  severity_rationale: string;
  location: string;
  route: string | null;
  param: string | null;
  snippet: string;
  exploit: string | null;
  status: string;
  patch_rationale: string | null;
  diff: string;
  lines_added: number;
  lines_removed: number;
  exploit_blocked: boolean;
  regression_passed: boolean;
  regression_checks: number;
  variants_blocked: number;
  variants_total: number;
  accepted: boolean;
}

export interface CodeTarget {
  target: string;
  sha256: string;
  engine: string;
  raw_alerts: number;
  confirmed: number;
  fixed: number;
  false_positives_dropped: number;
  precision_before: number;
  precision_after: number;
  issues: CodeIssue[];
  computed_at: number;
  duration_ms: number;
  cached: boolean;
}

export interface DocumentAnalysis {
  generated_at: number;
  document: {
    filename: string;
    kind: string;
    bytes: number;
    sha256: string;
    pages: number | null;
    pages_read: number | null;
    chars: number;
    truncated: boolean;
    excerpt: string;
    sample: string | null;
  };
  ps1: {
    provenance: { source: string; reason: string };
    detection: {
      detectors: string[];
      sentences_scanned: number;
      document_scan: DetectorVerdict[];
      flagged: DocumentFlaggedSentence[];
      flagged_total: number;
    };
    agent_note: string;
    decisions: DocumentDecision[];
    summary: Record<DecisionValue, number>;
    enforced: boolean;
  };
  ps2: {
    triggered: boolean;
    available: boolean;
    reason?: string;
    blocked_tools?: string[];
    registry?: Record<string, string>;
    targets?: CodeTarget[];
  };
}

/* ---- Benchmark (GET /v1/bench/latest) ---------------------------------- */

export interface BenchLatency {
  p50: number;
  p95: number;
  p99: number;
}

export interface BenchCase {
  id: string;
  label: string;
  attack_type: string;
  tool: string;
  source: string;
  expected: string;
  actual_on: string;
  actual_off: string;
  latency_ms_on: number;
  latency_ms_off: number;
  match_on: boolean;
}

export interface BenchRun {
  generated_at_utc: string;
  tool: string;
  n_cases: number;
  config: { detectors: string[]; enforce: string; synthetic: boolean; keyless: boolean };
  summary: {
    n_total: number;
    n_malicious: number;
    n_benign: number;
    n_approval: number;
    attack_success_off: number;
    attack_success_on: number;
    attack_held_on: number;
    attack_denied_on: number;
    false_positive_rate_benign: number;
    false_hold_rate_benign: number;
    approval_correctness: number;
    expected_match_rate_on: number;
    latency_ms_on: BenchLatency;
    latency_ms_off: BenchLatency;
  };
  cases: BenchCase[];
}

export interface BenchLatestResponse {
  latest: BenchRun | null;
}

/* ---- Closed-loop scorecard (GET /v1/evidence/scorecard) ----------------- */

export interface ScorecardGate {
  passed: boolean;
  actual: string | number | null;
  target: string | number | null;
}

export interface ScorecardIteration {
  iteration: number;
  confirmed_before: number | null;
  confirmed_after: number | null;
  runtime_attacks_blocked: unknown;
  deployed_exploit_blocked: boolean | null;
  regression_passed: boolean | null;
  elapsed_ms: number | null;
  status: string | null;
}

export type ScorecardResponse =
  | { available: false; reason: string }
  | {
      available: true;
      generated_at: string | null;
      threshold: number | null;
      gates: Record<string, ScorecardGate>;
      passed: boolean | null;
      loop: {
        status: string | null;
        converged: boolean | null;
        iterations_to_converge: number | null;
        residual_confirmed: number | null;
        iterations: ScorecardIteration[];
      };
      code_funnel: Record<string, unknown>;
      runtime_scenarios: Array<{
        id: string;
        label: string;
        attack_type: string;
        tool: string;
        expected_decision: string;
        actual_decision: string;
        passed: boolean;
      }>;
      code_cases: Array<{
        cwe: string;
        location: string;
        severity: string;
        exploit_confirmed: boolean;
        patch_accepted: boolean;
      }>;
      path: string;
    };

/* ---- Live MCP session (POST /v1/mcp/demo) ------------------------------ */

export interface McpDemoCall {
  label: string;
  tool: string;
  arguments_without_tag: Record<string, unknown>;
  asserted_source: string;
  token_attached: boolean;
  outcome: "executed" | "blocked";
  decision: DecisionValue | null;
  text: string;
  /** From the audit record this call wrote (null if it could not be matched). */
  call_id: string | null;
  audit_decision: DecisionValue | null;
  reasons: PolicyReason[];
}

export interface McpCallResponse {
  tools: string[];
  tool: string;
  arguments: Record<string, unknown>;
  asserted_source: "user" | "untrusted";
  token_attached: boolean;
  context_chars: number;
  outcome: "executed" | "blocked";
  decision: DecisionValue | null;
  text: string;
  call_ms: number;
  provenance_mode: "hmac" | "dev";
  call_id: string | null;
  audit_decision: DecisionValue | null;
  reasons: PolicyReason[];
}

export interface McpDemoResponse {
  transport: string;
  tools: string[];
  calls: McpDemoCall[];
  provenance_mode: "hmac" | "dev";
  duration_ms: number;
}

/* ---- Trust demo (POST /v1/trust/demo) ----------------------------------- */

export interface TrustDemoCheck {
  label: string;
  asserted_source: string;
  token: "none" | "valid" | "replayed";
  resolved_source: string;
  resolve_reason: string;
  decision: DecisionValue;
  reasons: PolicyReason[];
  call_id: string;
}

export interface TrustDemoResponse {
  tool: string;
  arguments: Record<string, unknown>;
  checks: TrustDemoCheck[];
}
