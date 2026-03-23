import type { JobState, TargetProfile } from "@/types/schema";

const BASE_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8001";
const API_KEY = process.env.NEXT_PUBLIC_API_KEY ?? "";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      "X-API-KEY": API_KEY,
      ...init?.headers,
    },
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`API ${res.status}: ${body}`);
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
  locations: {
    id: number;
    port: number;
    protocol: string | null;
    service: string | null;
    state: string | null;
  }[];
}

interface AssetsResponse {
  assets: AssetWithLocations[];
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
  targets: import("@/types/schema").Target[];
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
  expected_payout: number | null;
  actual_payout: number | null;
  submitted_at: string | null;
  created_at: string | null;
  updated_at: string | null;
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
  created_at: string | null;
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
  id: number;
  name: string;
  description: string | null;
  stages: StageConfig[];
  concurrency: { heavy: number; light: number } | null;
  created_at: string | null;
  updated_at: string | null;
}

/* ------------------------------------------------------------------ */
/* Scope Violations                                                   */
/* ------------------------------------------------------------------ */

export interface ScopeViolationRow {
  id: number;
  target_id: number;
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

  getAssets(targetId: number) {
    return request<AssetsResponse>(`/api/v1/assets?target_id=${targetId}`);
  },

  getVulnerabilities(targetId: number, severity?: string) {
    let qs = `?target_id=${targetId}`;
    if (severity) qs += `&severity=${severity}`;
    return request<VulnerabilitiesResponse>(`/api/v1/vulnerabilities${qs}`);
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

  updateTargetProfile(targetId: number, profile: { custom_headers?: Record<string, string>; rate_limits?: Record<string, number> }) {
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
    return request<{ bounties: BountyRow[] }>(`/api/v1/bounties${qs}`);
  },

  updateBounty(id: number, data: { status?: string; actual_payout?: number }) {
    return request<BountyRow>(`/api/v1/bounties/${id}`, {
      method: "PATCH",
      body: JSON.stringify(data),
    });
  },

  getBountyStats() {
    return request<{
      stats: {
        total: number;
        by_status: Record<string, number>;
        total_expected: number;
        total_paid: number;
      };
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
  }) {
    return request<{ keys: Record<string, boolean> }>(
      "/api/v1/config/api_keys",
      { method: "PUT", body: JSON.stringify(data) },
    );
  },

  enrichTarget(targetId: number) {
    return request<{ target_id: number; enrichment: unknown[] }>(
      `/api/v1/targets/${targetId}/enrich`,
      { method: "POST" },
    );
  },

  /* ------------------------------------------------------------------ */
  /* Custom Playbooks                                                    */
  /* ------------------------------------------------------------------ */

  getPlaybooks() {
    return request<{ playbooks: PlaybookRow[] }>("/api/v1/playbooks");
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
};
