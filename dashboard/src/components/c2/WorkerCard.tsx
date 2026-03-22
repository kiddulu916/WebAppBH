"use client";

import { useState } from "react";
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

interface WorkerCardProps {
  job: JobState;
  progress?: number;
  discoveredCount?: number;
}

const STATUS_DOT: Record<JobStatus, string> = {
  RUNNING: "bg-neon-green",
  QUEUED: "bg-neon-orange",
  PAUSED: "bg-warning",
  STOPPED: "bg-text-muted",
  COMPLETED: "bg-text-muted",
  FAILED: "bg-danger",
};

const STATUS_LABEL_COLOR: Record<JobStatus, string> = {
  RUNNING: "text-neon-green",
  QUEUED: "text-neon-orange",
  PAUSED: "text-warning",
  STOPPED: "text-text-muted",
  COMPLETED: "text-text-muted",
  FAILED: "text-danger",
};

export default function WorkerCard({
  job,
  progress,
  discoveredCount,
}: WorkerCardProps) {
  const [loading, setLoading] = useState<string | null>(null);

  async function handleAction(
    action: "pause" | "stop" | "restart" | "unpause",
  ) {
    setLoading(action);
    try {
      await api.controlWorker(job.container_name, action);
    } catch {
      /* handled by api client */
    } finally {
      setLoading(null);
    }
  }

  const isRunning = job.status === "RUNNING";
  const pct = progress ?? 0;

  return (
    <div
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
          <>
            {job.status === "RUNNING" && (
              <>
                <ActionButton
                  onClick={() => handleAction("pause")}
                  icon={Pause}
                  label="Pause"
                  hoverColor="hover:text-warning hover:bg-warning/10"
                />
                <ActionButton
                  onClick={() => handleAction("stop")}
                  icon={Square}
                  label="Stop"
                  hoverColor="hover:text-danger hover:bg-danger/10"
                />
              </>
            )}
            {job.status === "PAUSED" && (
              <>
                <ActionButton
                  onClick={() => handleAction("unpause")}
                  icon={Play}
                  label="Resume"
                  hoverColor="hover:text-neon-green hover:bg-neon-green-glow"
                />
                <ActionButton
                  onClick={() => handleAction("stop")}
                  icon={Square}
                  label="Stop"
                  hoverColor="hover:text-danger hover:bg-danger/10"
                />
              </>
            )}
            {(job.status === "COMPLETED" ||
              job.status === "FAILED" ||
              job.status === "STOPPED") && (
              <ActionButton
                onClick={() => handleAction("restart")}
                icon={RotateCcw}
                label="Restart"
                hoverColor="hover:text-neon-green hover:bg-neon-green-glow"
              />
            )}
            {job.status === "QUEUED" && (
              <ActionButton
                onClick={() => handleAction("restart")}
                icon={Play}
                label="Start"
                hoverColor="hover:text-neon-green hover:bg-neon-green-glow"
              />
            )}
          </>
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
}: {
  onClick: () => void;
  icon: React.ElementType;
  label: string;
  hoverColor: string;
}) {
  return (
    <button
      onClick={onClick}
      title={label}
      className={`flex items-center gap-1 rounded px-2 py-1 text-[10px] font-medium text-text-muted transition-colors ${hoverColor}`}
    >
      <Icon className="h-3 w-3" />
      {label}
    </button>
  );
}
