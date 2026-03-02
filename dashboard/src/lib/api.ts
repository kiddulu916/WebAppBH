import type { JobState, Target, TargetProfile } from "@/types/schema";

const BASE_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
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
/* Exported API object                                                */
/* ------------------------------------------------------------------ */

export const api = {
  createTarget(data: CreateTargetPayload) {
    return request<CreateTargetResponse>("/api/v1/targets", {
      method: "POST",
      body: JSON.stringify(data),
    });
  },

  getStatus(targetId?: number) {
    const qs = targetId != null ? `?target_id=${targetId}` : "";
    return request<StatusResponse>(`/api/v1/status${qs}`);
  },

  controlWorker(containerName: string, action: "pause" | "stop" | "restart") {
    return request<ControlResponse>("/api/v1/control", {
      method: "POST",
      body: JSON.stringify({ container_name: containerName, action }),
    });
  },

  sseUrl(targetId: number) {
    return `${BASE_URL}/api/v1/stream/${targetId}`;
  },
};
