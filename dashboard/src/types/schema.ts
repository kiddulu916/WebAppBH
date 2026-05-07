/**
 * WebAppBH — TypeScript interfaces matching the PostgreSQL schema.
 * Auto-generated for the Next.js dashboard (end-to-end type safety).
 *
 * Canonical source: shared/lib_webbh/database.py + shared/schema.sql
 */

// ---------------------------------------------------------------------------
// Enum-like union types
// ---------------------------------------------------------------------------

export type CloudProvider = "AWS" | "Azure" | "GCP" | "Other";

export type VulnSeverity = "info" | "low" | "medium" | "high" | "critical";

export type JobStatus = "QUEUED" | "RUNNING" | "PAUSED" | "STOPPED" | "COMPLETED" | "FAILED" | "KILLED";

export type AssetType =
  | "domain"
  | "ip"
  | "subdomain"
  | "sensitive_file"
  | "directory"
  | "error"
  | "form"
  | "upload"
  | "deadend"
  | "undetermined"
  | "cidr"
  | "url"
  | string;

// ---------------------------------------------------------------------------
// Shared timestamp fields (present on every row)
// ---------------------------------------------------------------------------

export interface Timestamps {
  created_at?: string; // ISO-8601 — not all endpoints return these
  updated_at?: string; // ISO-8601
}

// ---------------------------------------------------------------------------
// Target profile JSONB shape
// ---------------------------------------------------------------------------

export interface TargetProfile {
  in_scope_domains?: string[];
  out_scope_domains?: string[];
  in_scope_cidrs?: string[];
  in_scope_regex?: string[];
  rate_limits?: Array<{ amount: number; unit: string }> | Record<string, number>;
  custom_headers?: Record<string, string>;
  [key: string]: unknown;
}

// ---------------------------------------------------------------------------
// Table interfaces
// ---------------------------------------------------------------------------

export interface Target extends Timestamps {
  id: number;
  company_name: string;
  base_domain: string;
  target_profile: TargetProfile | null;
  last_playbook: string | null;
}

export interface TargetWithStats extends Target {
  asset_count: number;
  vuln_count: number;
  status: string;
  last_activity: string | null;
}

export interface Asset extends Timestamps {
  id: number;
  target_id: number;
  asset_type: AssetType;
  asset_value: string;
  source_tool: string | null;
  tech: Record<string, unknown> | null;
}

export interface Identity extends Timestamps {
  id: number;
  target_id: number;
  asn: string | null;
  organization: string | null;
  whois_data: Record<string, unknown> | null;
}

export interface Location extends Timestamps {
  id: number;
  asset_id: number;
  port: number;
  protocol: string | null;
  service: string | null;
  state: string | null;
}

export interface Observation extends Timestamps {
  id: number;
  asset_id: number;
  tech_stack: Record<string, unknown> | null;
  page_title: string | null;
  status_code: number | null;
  headers: Record<string, unknown> | null;
}

export interface CloudAsset extends Timestamps {
  id: number;
  target_id: number;
  provider: CloudProvider;
  asset_type: string;
  url: string | null;
  is_public: boolean;
  findings: Record<string, unknown> | null;
}

export interface Parameter extends Timestamps {
  id: number;
  asset_id: number;
  param_name: string;
  param_value: string | null;
  source_url: string | null;
}

export interface Vulnerability extends Timestamps {
  id: number;
  target_id: number;
  asset_id: number | null;
  severity: VulnSeverity;
  title: string;
  description: string | null;
  poc: string | null;
  source_tool: string | null;
  cvss_score: number | null;
}

export interface JobState extends Timestamps {
  id: number;
  target_id: number;
  container_name: string;
  current_phase: string | null;
  last_completed_stage: string | null;
  status: JobStatus;
  last_seen: string | null; // ISO-8601
  last_tool_executed: string | null;
  started_at: string | null; // ISO-8601
  completed_at: string | null; // ISO-8601
}

export interface Alert extends Timestamps {
  id: number;
  target_id: number;
  vulnerability_id: number | null;
  alert_type: string;
  message: string;
  is_read: boolean;
}

// ---------------------------------------------------------------------------
// Attack paths & execution state
// ---------------------------------------------------------------------------

export interface AttackPathStep {
  vuln_id: number;
  title: string;
  severity: VulnSeverity;
  asset_id: number | null;
  asset_value: string | null;
}

export interface AttackPath {
  id: number;
  severity: VulnSeverity;
  steps: AttackPathStep[];
  description: string;
}

export interface StageExecution {
  name: string;
  status: "pending" | "running" | "completed" | "failed" | "paused" | "stopped";
  tool: string | null;
  started_at?: string | null;
  last_seen?: string | null;
}

export interface WorkerExecution {
  name: string;
  status: "pending" | "queued" | "running" | "completed" | "failed" | "skipped";
  stages: StageExecution[];
  current_tool?: string;
  error?: string;
  skip_reason?: string;
}

export interface ExecutionState {
  target_id: number;
  playbook: string;
  workers: WorkerExecution[];
}

export interface GraphNode {
  id: string;
  label: string;
  type: "target" | "subdomain" | "ip" | "cidr" | "port" | "vulnerability";
  severity?: VulnSeverity;
}

export interface GraphEdge {
  source: string;
  target: string;
}

// ---------------------------------------------------------------------------
// Campaign
// ---------------------------------------------------------------------------

export type CampaignStatus = "pending" | "running" | "paused" | "complete" | "cancelled";

export interface Campaign extends Timestamps {
  id: number;
  name: string;
  description: string | null;
  status: CampaignStatus;
  scope_config: {
    in_scope: string[];
    out_of_scope: string[];
  } | null;
  rate_limit: number;
  has_credentials: boolean;
  started_at: string | null;
  completed_at: string | null;
}

// ---------------------------------------------------------------------------
// Pipeline / Worker State
// ---------------------------------------------------------------------------

export type PipelineWorkerStatus = "pending" | "queued" | "running" | "complete" | "failed" | "skipped";

export interface PipelineWorkerState {
  status: PipelineWorkerStatus;
  current_stage_index?: number;
  total_stages?: number;
  current_section_id?: string;
  last_tool_executed?: string;
  started_at?: string;
  completed_at?: string;
  skipped?: boolean;
  skip_reason?: string;
  error?: string;
}

export interface ResourceStatus {
  tier: "green" | "yellow" | "red" | "critical";
  cpu_percent: number;
  memory_percent: number;
  active_workers: number;
  thresholds: {
    green: { cpu: number; memory: number; workers: number };
    yellow: { cpu: number; memory: number; workers: number };
    red: { cpu: number; memory: number; workers: number };
  };
}

export const INFRA_WORKER_NAMES = [
  "proxy",
  "callback",
  "sandbox_worker",
] as const;

export const PIPELINE_WORKER_NAMES = [
  "info_gathering",
  "config_mgmt",
  "identity_mgmt",
  "authentication",
  "authorization",
  "session_mgmt",
  "input_validation",
  "error_handling",
  "cryptography",
  "business_logic",
  "client_side",
  "mobile_worker",
  "reasoning_worker",
  "chain_worker",
  "reporting",
] as const;

export const ALL_WORKER_NAMES = [...INFRA_WORKER_NAMES, ...PIPELINE_WORKER_NAMES] as const;

export type WorkerName = (typeof ALL_WORKER_NAMES)[number];

export const WORKER_STAGE_COUNTS: Record<string, number> = {
  proxy: 0,
  callback: 0,
  sandbox_worker: 0,
  info_gathering: 10,
  config_mgmt: 11,
  identity_mgmt: 5,
  authentication: 10,
  authorization: 4,
  session_mgmt: 9,
  input_validation: 19,
  error_handling: 2,
  cryptography: 4,
  business_logic: 9,
  client_side: 13,
  mobile_worker: 5,
  reasoning_worker: 3,
  chain_worker: 5,
  reporting: 4,
};

export const WORKER_DEPENDENCIES: Record<string, string[]> = {
  proxy: [],
  callback: [],
  sandbox_worker: [],
  info_gathering: [],
  config_mgmt: ["info_gathering"],
  identity_mgmt: ["config_mgmt"],
  authentication: ["identity_mgmt"],
  authorization: ["authentication"],
  session_mgmt: ["authentication"],
  input_validation: ["authentication"],
  error_handling: ["authorization", "session_mgmt", "input_validation"],
  cryptography: ["authorization", "session_mgmt", "input_validation"],
  business_logic: ["authorization", "session_mgmt", "input_validation"],
  client_side: ["authorization", "session_mgmt", "input_validation"],
  mobile_worker: ["authorization", "session_mgmt", "input_validation"],
  reasoning_worker: ["error_handling", "cryptography", "business_logic", "client_side", "mobile_worker"],
  chain_worker: ["reasoning_worker"],
  reporting: ["chain_worker"],
};

// ---------------------------------------------------------------------------
// Findings (extended vulnerability view)
// ---------------------------------------------------------------------------

export interface Finding extends Timestamps {
  id: number;
  target_id: number;
  severity: VulnSeverity;
  title: string;
  vuln_type: string;
  section_id: string | null;
  worker_type: string | null;
  stage_name: string | null;
  source_tool: string | null;
  confirmed: boolean;
  false_positive: boolean;
  description: string | null;
  evidence: Record<string, unknown> | null;
  remediation: string | null;
  created_at: string;
  target_domain?: string;
}

// ---------------------------------------------------------------------------
// Chain findings
// ---------------------------------------------------------------------------

export interface ChainFindingView {
  id: number;
  target_id: number;
  chain_description: string;
  severity: string;
  total_impact: string | null;
  linked_vulnerability_ids: number[] | null;
  created_at: string;
}

// ---------------------------------------------------------------------------
// Target hierarchy
// ---------------------------------------------------------------------------

export interface TargetNode {
  id: number;
  domain: string;
  target_type: "seed" | "child";
  priority: number;
  status: string;
  wildcard: boolean;
  wildcard_count: number | null;
  parent_target_id: number | null;
  worker_states: Record<string, PipelineWorkerState>;
  vulnerability_count: number;
  children?: TargetNode[];
}

// ---------------------------------------------------------------------------
// Scope & Credentials
// ---------------------------------------------------------------------------

export interface ScopeConfig {
  in_scope: string[];
  out_of_scope: string[];
}

export interface CredentialConfig {
  tester: {
    username: string;
    password: string;
    auth_type: "form" | "basic" | "bearer" | "oauth";
    login_url?: string;
  } | null;
  testing_user: {
    username: string;
    email: string;
    profile_url?: string;
  } | null;
}
