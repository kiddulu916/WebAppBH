/** SSE event types emitted by the orchestrator. */

export type SSEEventType =
  | "TOOL_PROGRESS"
  | "NEW_ASSET"
  | "CRITICAL_ALERT"
  | "WORKER_SPAWNED";

export interface SSEEvent {
  event: SSEEventType;
  target_id: number;
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
