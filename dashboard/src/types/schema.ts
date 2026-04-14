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

export type AssetType = "subdomain" | "ip" | "cidr" | "url" | string;

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
  rate_limits?: Record<string, number>;
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
  started_at: string | null;
  last_seen: string | null;
}

export interface ExecutionState {
  target_id: number;
  playbook: string;
  stages: StageExecution[];
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
