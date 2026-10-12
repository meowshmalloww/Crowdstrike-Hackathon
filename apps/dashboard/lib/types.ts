export type ApiResponse<T> = T | null;

export type EventRecord = {
  event_id: string;
  request_id: string;
  occurred_at: string;
  source_ip_pseudonym: string | null;
  route: string;
  method: string;
  status: number;
  duration_ms: number;
  origin: string;
  action: string;
  waf_rule_ids: number[];
  waf_anomaly_score: number | null;
  signals: Record<string, boolean>;
};

export type Incident = {
  id: string;
  status: string;
  first_seen_at: string;
  last_seen_at: string;
  classification: string;
  rank: number;
  risk_score: number;
  score_version: string;
  severity: string;
  model_status: string;
  jev_choice: string | null;
  jev_confidence: number | null;
  local_ai_status: string;
  local_ai_summary: string | null;
  explanation: string;
  score_contributions: Record<string, number>;
  evidence_event_ids: string[];
  estimated_impact: string;
  request_to_alert_latency_ms: number | null;
};

export type Policy = {
  id: string;
  action: string;
  match_spec: Record<string, string>;
  reason: string;
  source_incident_id: string | null;
  status: string;
  activated_at: string | null;
  expires_at: string;
  version: number;
};

export type Repair = {
  id: string;
  incident_id: string;
  repository: string;
  branch: string | null;
  commit_base: string;
  status: string;
  model_provider: string;
  diff_summary: string;
  diff?: string;
  checks: Array<{ test_name: string; exit_code: number; outcome: string; log_ref: string }>;
};

export type Metrics = {
  events_per_second: number;
  events_last_minute: number;
  total_events: number;
  open_incidents: number;
  honeypot_interactions: number;
  average_response_latency_ms: number | null;
  average_request_to_alert_latency_ms: number | null;
  last_event_at: string | null;
  telemetry_freshness: string;
  lab_mode: string;
};

export type DashboardData = {
  connected: boolean;
  metrics: Metrics | null;
  events: EventRecord[];
  incidents: Incident[];
  policies: Policy[];
  honeypot: Array<{ id: string; request_id: string; occurred_at: string; decoy_id: string; route: string; result_status: number }>;
  repairs: Repair[];
  integrations: Record<string, { status: string; role: string; note?: string; provider?: string | null; model?: string | null; api_base?: string | null }>;
  evaluation: { latest: null | { id: string; created_at: string; dataset: string; metrics: Record<string, unknown> }; dataset_label: string } | null;
  settings: Record<string, string | boolean> | null;
  audit: Array<{ id: string; principal_id: string; action: string; target: string; created_at: string; outcome: string; detail: Record<string, unknown> }>;
};
