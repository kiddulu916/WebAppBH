/** SSE event types emitted by the orchestrator. */

export type SSEEventType =
  | "TOOL_PROGRESS"
  | "NEW_ASSET"
  | "CRITICAL_ALERT"
  | "WORKER_SPAWNED"
  | "RECON_DIFF"
  | "SCOPE_DRIFT"
  | "AUTOSCALE_RECOMMENDATION"
  | "KILL_ALL"
  | "RERUN_STARTED"
  | "CLEAN_SLATE";

export interface SSEEvent {
  event: SSEEventType;
  target_id: number;
  timestamp?: string; // ISO-8601, added client-side on receipt
  [key: string]: unknown;
}

export interface ToolProgressEvent extends SSEEvent {
  event: "TOOL_PROGRESS";
  container: string;
  tool: string;
  progress: number;
  message: string;
}

export interface NewAssetEvent extends SSEEvent {
  event: "NEW_ASSET";
  asset_type: string;
  asset_value: string;
}

export interface CriticalAlertEvent extends SSEEvent {
  event: "CRITICAL_ALERT";
  alert_type: string;
  message: string;
  severity: string;
}

export interface WorkerSpawnedEvent extends SSEEvent {
  event: "WORKER_SPAWNED";
  container: string;
  image: string;
  phase: string;
}

export interface ReconDiffEvent extends SSEEvent {
  event: "RECON_DIFF";
  scan_number: number;
  added: string[];
  removed: string[];
  unchanged_count: number;
}

export interface ScopeDriftEvent extends SSEEvent {
  event: "SCOPE_DRIFT";
  asset_value: string;
  classification: string;
  provider: string | null;
}

export interface AutoscaleEvent extends SSEEvent {
  event: "AUTOSCALE_RECOMMENDATION";
  queue: string;
  worker: string;
  pending: number;
  action: string;
}

export interface KillAllEvent extends SSEEvent {
  event: "KILL_ALL";
  killed_count: number;
  containers: string[];
}

export interface RerunStartedEvent extends SSEEvent {
  event: "RERUN_STARTED";
  playbook_name: string;
}

export interface CleanSlateEvent extends SSEEvent {
  event: "CLEAN_SLATE";
}
