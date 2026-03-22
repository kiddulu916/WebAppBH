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
};
