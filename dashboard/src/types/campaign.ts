export interface Campaign {
  id: number;
  name: string;
  description: string | null;
  status: "pending" | "running" | "paused" | "complete" | "cancelled";
  scope_config: ScopeConfig | null;
  rate_limit: number;
  has_credentials: boolean;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
}

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

export interface WorkerState {
  status: "pending" | "queued" | "running" | "complete" | "failed" | "skipped";
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

export interface TargetNode {
  id: number;
  domain: string;
  target_type: "seed" | "child";
  priority: number;
  status: string;
  wildcard: boolean;
  wildcard_count: number | null;
  parent_target_id: number | null;
  worker_states: Record<string, WorkerState>;
  vulnerability_count: number;
  children?: TargetNode[];
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

export interface TargetEvent {
  event: string;
  worker?: string;
  target_id: number;
  timestamp: string;
  data?: Record<string, unknown>;
  stage_index?: number;
  section_id?: string;
  stage_name?: string;
  severity?: string;
  title?: string;
  error?: string;
  count?: number;
}

export interface Finding {
  id: number;
  target_id: number;
  severity: "critical" | "high" | "medium" | "low" | "info";
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

export interface ChainFindingView {
  id: number;
  target_id: number;
  chain_description: string;
  severity: string;
  total_impact: string | null;
  linked_vulnerability_ids: number[] | null;
  created_at: string;
}

export const WORKER_STAGE_COUNTS: Record<string, number> = {
  info_gathering: 10,
  config_mgmt: 11,
  identity_mgmt: 5,
  authentication: 10,
  authorization: 4,
  session_mgmt: 9,
  input_validation: 15,
  error_handling: 2,
  cryptography: 4,
  business_logic: 9,
  client_side: 13,
  chain_worker: 4,
  reporting: 1,
};
