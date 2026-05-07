import { toast } from "sonner";
import type { JobState, TargetProfile } from "@/types/schema";

const BASE_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8001";
const API_KEY = process.env.NEXT_PUBLIC_API_KEY ?? "";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${BASE_URL}${path}`, {
      ...init,
      headers: {
        "Content-Type": "application/json",
        "X-API-KEY": API_KEY,
        ...init?.headers,
      },
    });
  } catch {
    toast.error("Network error — is the orchestrator running?");
    throw new Error("Network error: unable to reach orchestrator");
  }

  if (!res.ok) {
    const body = await res.text();
    let detail = `API ${res.status}`;
    try {
      const parsed = JSON.parse(body);
      detail = parsed.detail ?? detail;
    } catch {
      if (body) detail = body;
    }
    toast.error(detail);
    throw new Error(detail);
  }

  if (res.status === 204 || res.headers.get("content-length") === "0") {
    return undefined as T;
  }

  return res.json() as Promise<T>;
}

/* ------------------------------------------------------------------ */
/* Targets                                                            */
/* ------------------------------------------------------------------ */

export interface CreateTargetPayload {
  company_name: string;
  base_domain: string;
  target_profile?: TargetProfile;
  playbook?: string;
}

interface CreateTargetResponse {
  target_id: number;
  company_name: string;
  base_domain: string;
  profile_path: string;
}

/* ------------------------------------------------------------------ */
/* Status                                                             */
/* ------------------------------------------------------------------ */

interface StatusResponse {
  jobs: JobState[];
}

/* ------------------------------------------------------------------ */
/* Control                                                            */
/* ------------------------------------------------------------------ */

interface ControlResponse {
  container: string;
  action: string;
  success: boolean;
}

/* ------------------------------------------------------------------ */
/* Assets                                                             */
/* ------------------------------------------------------------------ */

export interface AssetWithLocations {
  id: number;
  target_id: number;
  asset_type: string;
  asset_value: string;
  source_tool: string | null;
  created_at: string | null;
  updated_at: string | null;
  tech: Record<string, unknown> | null;
  scope_classification: string;
  associated_with_id: number | null;
  association_method: string | null;
  locations: {
    id: number;
    port: number;
    protocol: string | null;
    service: string | null;
    state: string | null;
  }[];
}

interface AssetsResponse {
  total: number;
  page: number;
  page_size: number;
  assets: AssetWithLocations[];
}

/* ------------------------------------------------------------------ */
/* Worker Health                                                       */
/* ------------------------------------------------------------------ */

export interface WorkerHealthEntry {
  name: string;
  status: string;
  image: string;
  started_at: string | null;
  cpu_percent: number | null;
  memory_mb: number | null;
  memory_limit_mb: number | null;
  restart_count: number;
  health_status: string | null;
}

interface WorkerHealthResponse {
  host: {
    cpu_percent: number;
    memory_percent: number;
    is_healthy: boolean;
  };
  workers: WorkerHealthEntry[];
}

/* ------------------------------------------------------------------ */
/* Vulnerabilities                                                    */
/* ------------------------------------------------------------------ */

interface VulnWithAsset {
  id: number;
  target_id: number;
  asset_id: number | null;
  asset_value: string | null;
  severity: string;
  title: string;
  description: string | null;
  poc: string | null;
  source_tool: string | null;
  created_at: string | null;
  updated_at: string | null;
}

interface VulnerabilitiesResponse {
  vulnerabilities: VulnWithAsset[];
}

/* ------------------------------------------------------------------ */
/* Cloud Assets                                                       */
/* ------------------------------------------------------------------ */

interface CloudAssetsResponse {
  cloud_assets: import("@/types/schema").CloudAsset[];
}

/* ------------------------------------------------------------------ */
/* Alerts                                                             */
/* ------------------------------------------------------------------ */

interface AlertsResponse {
  alerts: import("@/types/schema").Alert[];
}

/* ------------------------------------------------------------------ */
/* Targets (list)                                                     */
/* ------------------------------------------------------------------ */

interface TargetsResponse {
  targets: import("@/types/schema").TargetWithStats[];
}

/* ------------------------------------------------------------------ */
/* Bounties                                                           */
/* ------------------------------------------------------------------ */

export interface BountyRow {
  id: number;
  target_id: number;
  vulnerability_id: number;
  platform: string;
  status: string;
  submission_url: string | null;
  expected_payout: number | null;
  actual_payout: number | null;
  notes: string | null;
}

/* ------------------------------------------------------------------ */
/* Schedules                                                          */
/* ------------------------------------------------------------------ */

export interface ScheduleRow {
  id: number;
  target_id: number;
  cron_expression: string;
  playbook: string;
  enabled: boolean;
  last_run_at: string | null;
  next_run_at: string | null;
}

/* ------------------------------------------------------------------ */
/* Custom Playbooks                                                   */
/* ------------------------------------------------------------------ */

export interface StageConfig {
  name: string;
  enabled: boolean;
  tool_timeout?: number;
}

export interface PlaybookRow {
  id?: number;
  name: string;
  description: string | null;
  stages: StageConfig[];
  concurrency: { heavy: number; light: number } | null;
  builtin: boolean;
}

/* ------------------------------------------------------------------ */
/* Scope Violations                                                   */
/* ------------------------------------------------------------------ */

export interface ScopeViolationRow {
  id: number;
  tool_name: string;
  input_value: string;
  violation_type: string;
  created_at: string | null;
}

/* ------------------------------------------------------------------ */
/* Search                                                             */
/* ------------------------------------------------------------------ */

export interface SearchResult {
  type: "asset" | "vulnerability";
  id: number;
  value: string;
  subtype: string;
}

/* ------------------------------------------------------------------ */
/* LLM Insights / Triage                                               */
/* ------------------------------------------------------------------ */

export interface InsightRow {
  id: number;
  target_id: number;
  vulnerability_id: number;
  vulnerability_title: string;
  vulnerability_severity: string;
  severity_assessment: string | null;
  exploitability: string | null;
  false_positive_likelihood: number;
  chain_hypotheses: { with_vuln_id: number; description: string }[] | null;
  next_steps: string | null;
  bounty_estimate: { low: number; high: number; currency: string } | null;
  duplicate_likelihood: number;
  owasp_cwe: { owasp: string; cwe_id: number; cwe_name: string } | null;
  report_readiness_score: number;
  asset_criticality: string | null;
  confidence: number;
  created_at: string;
}

/* ------------------------------------------------------------------ */
/* Kill / Rerun / Clean Slate                                          */
/* ------------------------------------------------------------------ */

interface KillResponse {
  success: boolean;
  killed_count: number;
  containers: string[];
}

interface RerunResponse {
  success: boolean;
  target_id: number;
  playbook_name: string;
}

interface CleanSlateResponse {
  success: boolean;
  target_id: number;
}

/* ------------------------------------------------------------------ */
/* Exported API object                                                */
/* ------------------------------------------------------------------ */

export const api = {
  createTarget(data: CreateTargetPayload) {
    return request<CreateTargetResponse>("/api/v1/targets", {
      method: "POST",
      body: JSON.stringify(data),
    });
  },

  getTargets() {
    return request<TargetsResponse>("/api/v1/targets");
  },

  getStatus(targetId?: number) {
    const qs = targetId != null ? `?target_id=${targetId}` : "";
    return request<StatusResponse>(`/api/v1/status${qs}`);
  },

  getAssets(targetId: number, classification?: string) {
    let qs = `?target_id=${targetId}`;
    if (classification) qs += `&classification=${classification}`;
    return request<AssetsResponse>(`/api/v1/assets${qs}`);
  },

  updateAssetClassification(assetId: number, classification: string) {
    return request<{ id: number; scope_classification: string }>(
      `/api/v1/assets/${assetId}/classification`,
      { method: "PUT", body: JSON.stringify({ classification }) },
    );
  },

  bulkUpdateClassification(assetIds: number[], classification: string) {
    return request<{ updated: number; classification: string }>(
      "/api/v1/assets/bulk-classification",
      { method: "PUT", body: JSON.stringify({ asset_ids: assetIds, classification }) },
    );
  },

  getAssetChain(assetId: number) {
    return request<{
      chain: Array<{
        id: number;
        asset_value: string;
        asset_type: string;
        association_method: string | null;
      }>;
    }>(`/api/v1/assets/${assetId}/chain`);
  },

  getVulnerabilities(targetId: number, severity?: string) {
    let qs = `?target_id=${targetId}`;
    if (severity) qs += `&severity=${severity}`;
    return request<VulnerabilitiesResponse>(`/api/v1/vulnerabilities${qs}`);
  },

  getVulnerability(vulnId: number) {
    return request<VulnWithAsset>(`/api/v1/vulnerabilities/${vulnId}`);
  },

  updateVulnerability(vulnId: number, data: { false_positive?: boolean }) {
    return request<VulnWithAsset>(`/api/v1/vulnerabilities/${vulnId}`, {
      method: "PATCH",
      body: JSON.stringify(data),
    });
  },

  getCloudAssets(targetId: number) {
    return request<CloudAssetsResponse>(`/api/v1/cloud_assets?target_id=${targetId}`);
  },

  getAlerts(targetId: number, isRead?: boolean) {
    let qs = `?target_id=${targetId}`;
    if (isRead !== undefined) qs += `&is_read=${isRead}`;
    return request<AlertsResponse>(`/api/v1/alerts${qs}`);
  },

  markAlertRead(alertId: number) {
    return request<{ id: number; is_read: boolean }>(`/api/v1/alerts/${alertId}`, {
      method: "PATCH",
      body: JSON.stringify({ is_read: true }),
    });
  },

  updateTargetProfile(targetId: number, profile: { custom_headers?: Record<string, string>; rate_limits?: Array<{ amount: number; unit: string }> | Record<string, number> }) {
    return request<{ target_id: number; target_profile: import("@/types/schema").TargetProfile }>(`/api/v1/targets/${targetId}`, {
      method: "PATCH",
      body: JSON.stringify(profile),
    });
  },

  controlWorker(containerName: string, action: "pause" | "stop" | "restart" | "unpause") {
    return request<ControlResponse>("/api/v1/control", {
      method: "POST",
      body: JSON.stringify({ container_name: containerName, action }),
    });
  },

  triggerRescan(targetId: number) {
    return request<{ target_id: number; status: string; scan_number: number }>(
      `/api/v1/targets/${targetId}/rescan`,
      { method: "POST" },
    );
  },

  getDraftReport(vulnId: number, platform: "hackerone" | "bugcrowd" = "hackerone") {
    return request<{ vuln_id: number; platform: string; draft: string }>(
      `/api/v1/vulnerabilities/${vulnId}/draft?platform=${platform}`,
    );
  },

  getAttackGraph(targetId: number) {
    return request<{
      nodes: { id: string; label: string; type: string; severity?: string }[];
      edges: { source: string; target: string }[];
    }>(`/api/v1/targets/${targetId}/graph`);
  },

  getAttackPaths(targetId: number) {
    return request<{ target_id: number; paths: import("@/types/schema").AttackPath[] }>(
      `/api/v1/targets/${targetId}/attack-paths`,
    );
  },

  getExecutionState(targetId: number) {
    return request<import("@/types/schema").ExecutionState>(
      `/api/v1/targets/${targetId}/execution`,
    );
  },

  applyPlaybook(targetId: number, playbookName: string) {
    return request<{ target_id: number; playbook_name: string; applied: boolean }>(
      `/api/v1/targets/${targetId}/apply-playbook`,
      { method: "POST", body: JSON.stringify({ playbook_name: playbookName }) },
    );
  },

  getAssetLocations(assetId: number) {
    return request<{ asset_id: number; locations: import("@/types/schema").Location[] }>(
      `/api/v1/assets/${assetId}/locations`,
    );
  },

  getAssetVulnerabilities(assetId: number) {
    return request<{ asset_id: number; vulnerabilities: import("@/types/schema").Vulnerability[] }>(
      `/api/v1/assets/${assetId}/vulnerabilities`,
    );
  },

  getAssetCloud(assetId: number) {
    return request<{ asset_id: number; cloud_assets: import("@/types/schema").CloudAsset[] }>(
      `/api/v1/assets/${assetId}/cloud`,
    );
  },

  getCorrelations(targetId: number) {
    return request<{
      target_id: number;
      groups: {
        shared_assets: string[];
        severity: string;
        count: number;
        vuln_ids: number[];
        chain_description: string;
      }[];
    }>(`/api/v1/targets/${targetId}/correlations`);
  },

  getQueueHealth() {
    return request<{
      queues: Record<string, { pending: number; health: string }>;
    }>("/api/v1/queue_health");
  },

  sseUrl(targetId: number) {
    return `${BASE_URL}/api/v1/stream/${targetId}`;
  },

  /* ------------------------------------------------------------------ */
  /* Bounty Tracker                                                      */
  /* ------------------------------------------------------------------ */

  createBounty(data: {
    target_id: number;
    vulnerability_id: number;
    platform: string;
    expected_payout?: number;
  }) {
    return request<{ id: number; status: string }>("/api/v1/bounties", {
      method: "POST",
      body: JSON.stringify(data),
    });
  },

  getBounties(targetId: number, status?: string) {
    let qs = `?target_id=${targetId}`;
    if (status) qs += `&status=${status}`;
    return request<BountyRow[]>(`/api/v1/bounties${qs}`);
  },

  updateBounty(id: number, data: { status?: string; actual_payout?: number }) {
    return request<BountyRow>(`/api/v1/bounties/${id}`, {
      method: "PATCH",
      body: JSON.stringify(data),
    });
  },

  getBountyStats() {
    return request<{
      total_submitted: number;
      total_accepted: number;
      total_paid: number;
      total_payout: number;
      by_platform: Record<string, number>;
      by_target: Record<string, number>;
    }>("/api/v1/bounties/stats");
  },

  /* ------------------------------------------------------------------ */
  /* Scheduling                                                          */
  /* ------------------------------------------------------------------ */

  createSchedule(data: {
    target_id: number;
    cron_expression: string;
    playbook?: string;
  }) {
    return request<{ id: number }>("/api/v1/schedules", {
      method: "POST",
      body: JSON.stringify(data),
    });
  },

  getSchedules(targetId?: number) {
    const qs = targetId ? `?target_id=${targetId}` : "";
    return request<ScheduleRow[]>(`/api/v1/schedules${qs}`);
  },

  updateSchedule(
    id: number,
    data: { enabled?: boolean; cron_expression?: string },
  ) {
    return request<ScheduleRow>(`/api/v1/schedules/${id}`, {
      method: "PATCH",
      body: JSON.stringify(data),
    });
  },

  deleteSchedule(id: number) {
    return request<void>(`/api/v1/schedules/${id}`, { method: "DELETE" });
  },

  /* ------------------------------------------------------------------ */
  /* Intel Enrichment / API Keys                                         */
  /* ------------------------------------------------------------------ */

  getApiKeyStatus() {
    return request<{ keys: Record<string, boolean> }>("/api/v1/config/api_keys");
  },

  updateApiKeys(data: {
    shodan_api_key?: string;
    securitytrails_api_key?: string;
    censys_api_id?: string;
    censys_api_secret?: string;
  }) {
    return request<{ keys: Record<string, boolean> }>(
      "/api/v1/config/api_keys",
      { method: "PUT", body: JSON.stringify(data) },
    );
  },

  enrichTarget(targetId: number) {
    return request<{
      target_id: number;
      domain: string;
      sources: {
        shodan: { subdomains: number; ips: number; ports: number };
        securitytrails: { subdomains: number; ips: number };
      };
      total_subdomains: number;
      total_ips: number;
      inserted_subdomains: number;
      inserted_ips: number;
    }>(
      `/api/v1/targets/${targetId}/enrich`,
      { method: "POST" },
    );
  },

  /* ------------------------------------------------------------------ */
  /* Custom Playbooks                                                    */
  /* ------------------------------------------------------------------ */

  getPlaybooks() {
    return request<PlaybookRow[]>("/api/v1/playbooks");
  },

  createPlaybook(data: {
    name: string;
    description?: string;
    stages: StageConfig[];
    concurrency?: { heavy: number; light: number };
  }) {
    return request<PlaybookRow>("/api/v1/playbooks", {
      method: "POST",
      body: JSON.stringify(data),
    });
  },

  updatePlaybook(
    id: number,
    data: {
      name?: string;
      description?: string;
      stages?: StageConfig[];
      concurrency?: { heavy: number; light: number };
    },
  ) {
    return request<PlaybookRow>(`/api/v1/playbooks/${id}`, {
      method: "PATCH",
      body: JSON.stringify(data),
    });
  },

  deletePlaybook(id: number) {
    return request<void>(`/api/v1/playbooks/${id}`, { method: "DELETE" });
  },

  /* ------------------------------------------------------------------ */
  /* Export                                                              */
  /* ------------------------------------------------------------------ */

  exportFindings(
    targetId: number,
    format: "json" | "csv" | "markdown" = "json",
  ) {
    return request<unknown>(
      `/api/v1/targets/${targetId}/export?format=${format}`,
    );
  },

  /* ------------------------------------------------------------------ */
  /* Scope Violations                                                    */
  /* ------------------------------------------------------------------ */

  getScopeViolations(targetId: number) {
    return request<{ violations: ScopeViolationRow[] }>(
      `/api/v1/scope_violations?target_id=${targetId}`,
    );
  },

  /* ------------------------------------------------------------------ */
  /* Search                                                              */
  /* ------------------------------------------------------------------ */

  search(targetId: number, query: string) {
    return request<{
      query: string;
      results: SearchResult[];
    }>(`/api/v1/search?target_id=${targetId}&q=${encodeURIComponent(query)}`);
  },

  /* ------------------------------------------------------------------ */
  /* Kill / Rerun / Clean Slate                                          */
  /* ------------------------------------------------------------------ */

  kill() {
    return request<KillResponse>("/api/v1/kill", { method: "POST" });
  },

  rerun(targetId: number, playbookName: string) {
    return request<RerunResponse>("/api/v1/rerun", {
      method: "POST",
      body: JSON.stringify({ target_id: targetId, playbook_name: playbookName }),
    });
  },

  cleanSlate(targetId: number) {
    return request<CleanSlateResponse>(`/api/v1/targets/${targetId}/clean-slate`, {
      method: "POST",
    });
  },

  deleteTarget(targetId: number) {
    return request<{ success: boolean; target_id: number }>(
      `/api/v1/targets/${targetId}`,
      { method: "DELETE" },
    );
  },

  /* ------------------------------------------------------------------ */
  /* Campaigns                                                           */
  /* ------------------------------------------------------------------ */

  getCampaigns() {
    return request<{ campaigns: import("@/types/schema").Campaign[] }>("/api/v1/campaigns");
  },

  getCampaign(id: number) {
    return request<import("@/types/schema").Campaign>(`/api/v1/campaigns/${id}`);
  },

  createCampaign(data: { name: string; description?: string; scope_config?: unknown; rate_limit?: number; has_credentials?: boolean }) {
    return request<{ id: number; name: string; status: string }>("/api/v1/campaigns", {
      method: "POST",
      body: JSON.stringify(data),
    });
  },

  updateCampaign(id: number, data: { name?: string; description?: string; status?: string }) {
    return request<{ id: number; status: string }>(`/api/v1/campaigns/${id}`, {
      method: "PATCH",
      body: JSON.stringify(data),
    });
  },

  /* ------------------------------------------------------------------ */
  /* Worker Health                                                        */
  /* ------------------------------------------------------------------ */

  getWorkerHealth() {
    return request<WorkerHealthResponse>("/api/v1/worker_health");
  },

  getResourceStatus() {
    return request<import("@/types/schema").ResourceStatus>("/api/v1/resources/status");
  },

  getReports(targetId?: number) {
    const qs = targetId ? `?target_id=${targetId}` : "";
    return request<{ reports: { id: string; title: string; severity: string; target_domain: string; type: string; created_at: string }[] }>(
      `/api/v1/reports${qs}`,
    );
  },

  getReport(reportId: string) {
    return request<{ id: string; title: string; content: string }>(`/api/v1/reports/${reportId}`);
  },

  downloadReport(reportId: string) {
    return `${BASE_URL}/api/v1/reports/${reportId}/download`;
  },

  /* ------------------------------------------------------------------ */
  /* LLM Insights / Triage                                               */
  /* ------------------------------------------------------------------ */

  getInsights(targetId: number) {
    return request<{ insights: InsightRow[] }>(
      `/api/v1/targets/${targetId}/insights`,
    );
  },
};
