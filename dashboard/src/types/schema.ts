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

export type JobStatus = "QUEUED" | "RUNNING" | "COMPLETED" | "FAILED";

export type AssetType = "subdomain" | "ip" | "cidr" | "url" | string;

// ---------------------------------------------------------------------------
// Shared timestamp fields (present on every row)
// ---------------------------------------------------------------------------

interface Timestamps {
  created_at: string; // ISO-8601
  updated_at: string; // ISO-8601
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
}

export interface Asset extends Timestamps {
  id: number;
  target_id: number;
  asset_type: AssetType;
  asset_value: string;
  source_tool: string | null;
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
}

export interface JobState extends Timestamps {
  id: number;
  target_id: number;
  container_name: string;
  current_phase: string | null;
  status: JobStatus;
  last_seen: string | null; // ISO-8601
  last_tool_executed: string | null;
}

export interface Alert extends Timestamps {
  id: number;
  target_id: number;
  vulnerability_id: number | null;
  alert_type: string;
  message: string;
  is_read: boolean;
}
