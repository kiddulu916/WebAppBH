const BASE = "http://localhost:8001/api/v1";
const API_KEY = process.env.WEB_APP_BH_API_KEY ?? "";

const headers: Record<string, string> = {
  "Content-Type": "application/json",
  ...(API_KEY ? { "X-API-KEY": API_KEY } : {}),
};

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: { ...headers, ...init?.headers },
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`API ${res.status} ${path}: ${text}`);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

/** createTarget with automatic killAll retry on 409 (race with event engine). */
async function createTargetWithRetry(data: {
  company_name: string;
  base_domain: string;
  target_profile?: Record<string, unknown>;
  playbook?: string;
}): Promise<{ target_id: number; company_name: string; base_domain: string }> {
  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      return await req<{ target_id: number; company_name: string; base_domain: string }>(
        "/targets",
        { method: "POST", body: JSON.stringify(data) },
      );
    } catch (err) {
      if (err instanceof Error && err.message.includes("409") && attempt < 4) {
        await req<{ success: boolean }>("/kill", { method: "POST" });
        await new Promise((r) => setTimeout(r, 500));
        continue;
      }
      throw err;
    }
  }
  throw new Error("createTarget: exhausted retries");
}

export const apiClient = {
  health: () => req<{ status: string }>("/health"),

  createTarget: (data: {
    company_name: string;
    base_domain: string;
    target_profile?: Record<string, unknown>;
    playbook?: string;
  }) => createTargetWithRetry(data),

  getTargets: () =>
    req<{
      targets: Array<{
        id: number;
        company_name: string;
        base_domain: string;
        asset_count: number;
        vuln_count: number;
        status: string;
      }>;
    }>("/targets"),

  deleteTarget: (id: number) =>
    req<{ success: boolean }>(`/targets/${id}`, { method: "DELETE" }),

  cleanSlate: (id: number) =>
    req<{ success: boolean }>(`/targets/${id}/clean-slate`, { method: "POST" }),

  rescan: (id: number) =>
    req<{ target_id: number; status: string }>(
      `/targets/${id}/rescan`,
      { method: "POST" },
    ),

  updateTargetProfile: (
    id: number,
    data: {
      custom_headers?: Record<string, string>;
      rate_limits?: Record<string, number>;
    },
  ) =>
    req<{ target_id: number; target_profile: Record<string, unknown> }>(
      `/targets/${id}`,
      { method: "PATCH", body: JSON.stringify(data) },
    ),

  getAssets: (targetId: number) =>
    req<{
      assets: Array<{ id: number; asset_type: string; asset_value: string }>;
    }>(`/assets?target_id=${targetId}`),

  getVulns: (targetId: number) =>
    req<{
      vulnerabilities: Array<{
        id: number;
        severity: string;
        title: string;
      }>;
    }>(`/vulnerabilities?target_id=${targetId}`),

  getCloudAssets: (targetId: number) =>
    req<{
      cloud_assets: Array<{
        id: number;
        provider: string;
        asset_type: string;
      }>;
    }>(`/cloud_assets?target_id=${targetId}`),

  getJobs: (targetId: number) =>
    req<{
      jobs: Array<{
        id: number;
        container_name: string;
        status: string;
        current_phase: string | null;
      }>;
    }>(`/status?target_id=${targetId}`),

  createBounty: (data: {
    target_id: number;
    vulnerability_id: number;
    platform: string;
    expected_payout?: number;
  }) =>
    req<{ id: number; status: string }>("/bounties", {
      method: "POST",
      body: JSON.stringify(data),
    }),

  getBounties: (targetId: number) =>
    req<Array<{ id: number; status: string; platform: string }>>(
      `/bounties?target_id=${targetId}`,
    ),

  updateBounty: (
    id: number,
    data: { status?: string; actual_payout?: number },
  ) =>
    req<{ id: number; status: string }>(`/bounties/${id}`, {
      method: "PATCH",
      body: JSON.stringify(data),
    }),

  createSchedule: (data: {
    target_id: number;
    cron_expression: string;
    playbook?: string;
  }) =>
    req<{ id: number }>("/schedules", {
      method: "POST",
      body: JSON.stringify(data),
    }),

  getSchedules: (targetId: number) =>
    req<Array<{ id: number; enabled: boolean; cron_expression: string }>>(
      `/schedules?target_id=${targetId}`,
    ),

  deleteSchedule: (id: number) =>
    req<void>(`/schedules/${id}`, { method: "DELETE" }),

  seedTestData: (targetId: number) =>
    req<{ seeded: boolean; asset_ids: number[]; vuln_ids: number[]; job_ids: number[] }>("/test/seed", {
      method: "POST",
      body: JSON.stringify({ target_id: targetId }),
    }),

  emitTestEvent: (targetId: number, eventData: Record<string, unknown>) =>
    req<{ emitted: boolean }>("/test/emit-event", {
      method: "POST",
      body: JSON.stringify({ target_id: targetId, event_data: eventData }),
    }),

  killAll: () =>
    req<{ success: boolean; killed_count: number }>("/kill", { method: "POST" }),

  search: (targetId: number, query: string) =>
    req<{ results: Array<{ type: string; id: number; value: string }> }>(
      `/search?target_id=${targetId}&q=${encodeURIComponent(query)}`,
    ),

  getPlaybooks: () =>
    req<Array<{ id?: number; name: string; stages: Array<{ name: string; enabled: boolean }> }>>(
      "/playbooks",
    ),

  applyPlaybook: (targetId: number, playbookName: string) =>
    req<{ applied: boolean }>(`/targets/${targetId}/apply-playbook`, {
      method: "POST",
      body: JSON.stringify({ playbook_name: playbookName }),
    }),

  getExecutionState: (targetId: number) =>
    req<{ stages: Array<{ name: string; status: string; tool: string | null }> }>(
      `/targets/${targetId}/execution`,
    ),

  getAttackGraph: (targetId: number) =>
    req<{ nodes: Array<{ id: string; label: string; type: string }>; edges: Array<{ source: string; target: string }> }>(
      `/targets/${targetId}/graph`,
    ),

  getAttackPaths: (targetId: number) =>
    req<{ paths: Array<{ id: number; severity: string; steps: Array<{ vuln_id: number; title: string }> }> }>(
      `/targets/${targetId}/attack-paths`,
    ),

  controlWorker: (containerName: string, action: string) =>
    req<{ success: boolean }>("/control", {
      method: "POST",
      body: JSON.stringify({ container_name: containerName, action }),
    }),

  updateSchedule: (id: number, data: { enabled?: boolean }) =>
    req<{ id: number; enabled: boolean }>(`/schedules/${id}`, {
      method: "PATCH",
      body: JSON.stringify(data),
    }),
};
