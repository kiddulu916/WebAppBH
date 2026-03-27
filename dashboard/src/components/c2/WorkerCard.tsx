"use client";

import { useMemo, useState } from "react";
import {
  Play,
  Pause,
  Square,
  RotateCcw,
  Loader2,
  Container,
  Zap,
} from "lucide-react";
import { api } from "@/lib/api";
import type { JobState, JobStatus } from "@/types/schema";

type WorkerAction = "pause" | "stop" | "restart" | "unpause";

interface ButtonConfig {
  action: WorkerAction;
  icon: React.ElementType;
  label: string;
  hoverColor: string;
}

function getButtons(status: JobStatus): ButtonConfig[] {
  switch (status) {
    case "RUNNING":
      return [
        { action: "pause", icon: Pause, label: "Pause", hoverColor: "hover:text-warning hover:bg-warning/10" },
        { action: "stop", icon: Square, label: "Stop", hoverColor: "hover:text-danger hover:bg-danger/10" },
      ];
    case "PAUSED":
      return [
        { action: "unpause", icon: Play, label: "Resume", hoverColor: "hover:text-neon-green hover:bg-neon-green-glow" },
        { action: "stop", icon: Square, label: "Stop", hoverColor: "hover:text-danger hover:bg-danger/10" },
      ];
    case "COMPLETED":
    case "FAILED":
    case "STOPPED":
      return [
        { action: "restart", icon: RotateCcw, label: "Restart", hoverColor: "hover:text-neon-green hover:bg-neon-green-glow" },
      ];
    case "QUEUED":
      return [
        { action: "restart", icon: Play, label: "Start", hoverColor: "hover:text-neon-green hover:bg-neon-green-glow" },
      ];
    default:
      return [];
  }
}

interface WorkerCardProps {
  job: JobState;
  progress?: number;
  discoveredCount?: number;
  onActionComplete?: () => void;
}

const STATUS_DOT: Record<JobStatus, string> = {
  RUNNING: "bg-neon-green",
  QUEUED: "bg-neon-orange",
  PAUSED: "bg-warning",
  STOPPED: "bg-text-muted",
  COMPLETED: "bg-text-muted",
  FAILED: "bg-danger",
  KILLED: "bg-danger",
};

const STATUS_LABEL_COLOR: Record<JobStatus, string> = {
  RUNNING: "text-neon-green",
  QUEUED: "text-neon-orange",
  PAUSED: "text-warning",
  STOPPED: "text-text-muted",
  COMPLETED: "text-text-muted",
  FAILED: "text-danger",
  KILLED: "text-danger",
};

export default function WorkerCard({
  job,
  progress,
  discoveredCount,
  onActionComplete,
}: WorkerCardProps) {
  const [loading, setLoading] = useState<string | null>(null);
  const buttons = useMemo(() => getButtons(job.status), [job.status]);

  async function handleAction(
    action: "pause" | "stop" | "restart" | "unpause",
  ) {
    setLoading(action);
    try {
      await api.controlWorker(job.container_name, action);
      onActionComplete?.();
    } catch {
      // toast shown by api.request()
    } finally {
      setLoading(null);
    }
  }

  const isRunning = job.status === "RUNNING";
  const pct = progress ?? 0;

  return (
    <div
      data-testid={`worker-card-${job.container_name}`}
      className={`rounded-lg border bg-bg-tertiary p-3 transition-all ${
        isRunning
          ? "animate-pulse-green border-neon-green/20"
          : "border-border"
      }`}
    >
      {/* Header: name + status dot */}
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <Container className="h-3.5 w-3.5 shrink-0 text-text-muted" />
          <span className="truncate font-mono text-xs text-text-primary">
            {job.container_name}
          </span>
        </div>
        <div className="flex items-center gap-1.5 shrink-0">
          <span
            className={`h-2 w-2 rounded-full ${STATUS_DOT[job.status]}`}
          />
          <span
            className={`text-[10px] font-semibold uppercase ${STATUS_LABEL_COLOR[job.status]}`}
          >
            {job.status}
          </span>
        </div>
      </div>

      {/* Phase + last tool */}
      <div className="mt-2 flex items-center gap-1.5">
        {job.current_phase && (
          <span className="rounded bg-bg-surface px-1.5 py-0.5 font-mono text-[10px] text-text-secondary">
            {job.current_phase}
          </span>
        )}
        {job.last_tool_executed && (
          <span className="rounded bg-neon-orange-glow px-1.5 py-0.5 font-mono text-[10px] text-neon-orange">
            {job.last_tool_executed}
          </span>
        )}
      </div>

      {/* Progress bar */}
      <div className="mt-2.5">
        <div className="flex items-center justify-between text-[10px]">
          <span className="text-text-muted">Progress</span>
          <span className="font-mono text-text-secondary">{pct}%</span>
        </div>
        <div className="progress-bar mt-1">
          <div
            className={
              isRunning ? "progress-fill" : "progress-fill-orange"
            }
            style={{ width: `${Math.min(pct, 100)}%` }}
          />
        </div>
      </div>

      {/* Discovered count */}
      {discoveredCount != null && discoveredCount > 0 && (
        <div className="mt-2 flex items-center gap-1 text-[10px]">
          <Zap className="h-3 w-3 text-neon-green" />
          <span className="font-mono text-neon-green">
            {discoveredCount}
          </span>
          <span className="text-text-muted">items discovered</span>
        </div>
      )}

      {/* Action buttons */}
      <div className="mt-3 flex items-center gap-1 border-t border-border pt-2.5">
        {loading ? (
          <Loader2 className="h-3.5 w-3.5 animate-spin text-accent" />
        ) : (
          buttons.map((btn) => (
            <ActionButton
              key={btn.action}
              onClick={() => handleAction(btn.action)}
              icon={btn.icon}
              label={btn.label}
              hoverColor={btn.hoverColor}
              testId={
                btn.action === "pause"
                  ? "worker-pause-btn"
                  : btn.action === "stop"
                    ? "worker-stop-btn"
                    : btn.action === "unpause"
                      ? "worker-resume-btn"
                      : undefined
              }
            />
          ))
        )}
      </div>
    </div>
  );
}

function ActionButton({
  onClick,
  icon: Icon,
  label,
  hoverColor,
  testId,
}: {
  onClick: () => void;
  icon: React.ElementType;
  label: string;
  hoverColor: string;
  testId?: string;
}) {
  return (
    <button
      onClick={onClick}
      title={label}
      data-testid={testId}
      className={`flex items-center gap-1 rounded px-2 py-1 text-[10px] font-medium text-text-muted transition-colors ${hoverColor}`}
    >
      <Icon className="h-3 w-3" />
      {label}
    </button>
  );
}
