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
