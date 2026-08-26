export type Policy = "allow" | "block";

export interface RecentRun {
  run_id: number;
  server_id: string;
  tool_name: string;
  timestamp: string;
  latency_ms: number | null;
  notes: string | null;
  preview: string | null;
}

export interface RecentScan {
  server_id: string;
  overall_risk_level: string | null;
  provider: string | null;
  scanned_at: string;
}

export interface Overview {
  server_count: number;
  tool_count: number;
  blocked_tools: number;
  runs_24h: number;
  risk_distribution: Record<string, number>;
  effect_distribution: Record<string, number>;
  recent_activity: RecentRun[];
  recent_scans: RecentScan[];
  finding_counts: Record<string, number>;
  tool_risk_distribution: Record<string, number>;
  last_scan_at: string | null;
}

export interface ServerRow {
  server_id: string;
  transport: string;
  command: string | null;
  url: string | null;
  registered_at: string;
  tool_count: number;
  latest_scan_risk: string | null;
  latest_scan_at: string | null;
  latest_scan_provider: string | null;
  last_run_at: string | null;
}

export interface ServerDetail {
  server_id: string;
  transport: string;
  command: string | null;
  url: string | null;
  registered_at: string;
  args: string[];
  source_hash: {
    github_url: string | null;
    files_hash: string;
    first_seen_at: string;
    last_checked_at: string;
  } | null;
}

export interface Tool {
  tool_id: string;
  server_id: string;
  tool_name: string;
  description: string | null;
  discovered_at: string;
  effect_class: string;
  retry_safety: string;
  destructiveness: string;
  latency_p50_ms: number | null;
  latency_p95_ms: number | null;
  failure_rate: number | null;
  output_size_p95_bytes: number | null;
  run_count: number;
  policy: Policy | null;
}

export interface Paged<T> {
  items: T[];
  total: number;
  page: number;
  limit: number;
}

export interface ToolRunLite {
  run_id: number;
  timestamp: string;
  success: number;
  latency_ms: number | null;
  output_size: number | null;
  notes: string | null;
  output_preview: string | null;
}

export interface ToolDetail {
  tool_id: string;
  server_id: string;
  tool_name: string;
  description: string | null;
  schema: Record<string, unknown>;
  discovered_at: string;
  profile: Record<string, unknown> | null;
  policy: Policy | null;
  recent_runs: ToolRunLite[];
}

export interface Finding {
  name: string;
  risk_level: string;
  finding?: string;
  exploitation_scenario?: string;
  remediation?: string;
  risk_tags?: string[];
  mitre_techniques?: string[];
  server_id: string;
  scanned_at: string;
  provider?: string;
}

export interface ServerRisk {
  risk: string;
  risk_level: string;
  tools_involved?: string[];
  server_id: string;
  scanned_at?: string;
}

export interface FindingsResponse {
  items: Finding[];
  server_risks: ServerRisk[];
  counts: Record<string, number>;
  total: number;
}

export interface Scan {
  scan_id: number;
  server_id: string;
  provider: string | null;
  model_id: string | null;
  overall_risk_level: string | null;
  summary_text: string | null;
  tool_findings: Omit<Finding, "server_id" | "scanned_at">[];
  server_risks: Omit<ServerRisk, "server_id">[];
  scanned_at: string;
}

export interface Snapshot {
  snapshot_id: number;
  snapshot_at: string;
  tool_names: string[];
  tools_hash: string;
  drift_from_previous: boolean;
}

export interface Run {
  run_id: number;
  tool_id: string;
  timestamp: string;
  success: number;
  is_tool_error: number;
  latency_ms: number | null;
  output_size: number | null;
  notes: string | null;
  output_preview: string | null;
  server_id: string;
  tool_name: string;
}

export interface RunsResponse {
  items: Run[];
  total: number;
  limit: number;
}

export interface RunStats {
  series: { hour: string; runs: number; failures: number; failure_rate: number; latency_p95: number | null }[];
  hours: number;
}

export interface Activity {
  days: string[];
  tools: Record<string, number[]>;
  servers: Record<string, number[]>;
}

export interface PolicyRow {
  server_id: string;
  tool_name: string;
  policy: Policy;
  set_at: string;
  description: string | null;
}

export interface GraphObject {
  id: string;
  type: string;
  name: string;
  source: string;
  metadata: Record<string, unknown>;
}

export interface GraphRelation {
  source: string;
  target: string;
  relation: string;
  metadata: Record<string, unknown>;
}

export interface GraphData {
  objects: GraphObject[];
  relations: GraphRelation[];
}

export interface ScanResult {
  status: "completed" | "failed";
  error?: string;
  overall_risk_level?: string | null;
  finished_at: string;
}

export interface ScanStatus {
  current: string | null;
  queue: string[];
  results: Record<string, ScanResult>;
}

export interface Discovered {
  discovery_id: string;
  client: string;
  client_name: string;
  scope: string;
  config_path: string;
  server_name: string;
  transport: string;
  command: string | null;
  args_json: string | null;
  url: string | null;
  confidence: string | null;
  last_seen_at: string;
}

export interface RegisterInput {
  server_id: string;
  transport?: string;
  command?: string;
  args?: string[];
  url?: string;
  env?: Record<string, string>;
  headers?: Record<string, string>;
  github_url?: string;
}
