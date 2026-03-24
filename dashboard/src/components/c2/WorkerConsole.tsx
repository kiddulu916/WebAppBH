"use client";

import { useState } from "react";
import {
  Play,
  Pause,
  Square,
  RotateCcw,
  Loader2,
  Container,
} from "lucide-react";
import { api } from "@/lib/api";
import type { JobState, JobStatus } from "@/types/schema";

const STATUS_COLORS: Record<JobStatus, string> = {
  RUNNING: "text-success",
  QUEUED: "text-warning",
  PAUSED: "text-warning",
  STOPPED: "text-text-muted",
  COMPLETED: "text-text-muted",
  FAILED: "text-danger",
  KILLED: "text-danger",
};

const STATUS_DOT: Record<JobStatus, string> = {
  RUNNING: "bg-success",
  QUEUED: "bg-warning",
  PAUSED: "bg-warning",
  STOPPED: "bg-text-muted",
  COMPLETED: "bg-text-muted",
  FAILED: "bg-danger",
  KILLED: "bg-danger",
};

type WorkerAction = "pause" | "stop" | "restart" | "unpause";

interface ActionBtn {
  action: WorkerAction;
  icon: React.ElementType;
  label: string;
  hoverColor: string;
}

function actionButtons(status: JobStatus): ActionBtn[] {
  switch (status) {
    case "RUNNING":
      return [
        { action: "pause", icon: Pause, label: "Pause", hoverColor: "hover:text-warning" },
        { action: "stop", icon: Square, label: "Stop", hoverColor: "hover:text-danger" },
      ];
    case "PAUSED":
      return [
        { action: "unpause", icon: Play, label: "Resume", hoverColor: "hover:text-success" },
        { action: "stop", icon: Square, label: "Stop", hoverColor: "hover:text-danger" },
      ];
    case "COMPLETED":
    case "FAILED":
    case "STOPPED":
      return [
        { action: "restart", icon: RotateCcw, label: "Relaunch", hoverColor: "hover:text-success" },
      ];
    case "QUEUED":
      return [
        { action: "restart", icon: Play, label: "Start now", hoverColor: "hover:text-success" },
      ];
    default:
      return [];
  }
}

export default function WorkerConsole({ jobs }: { jobs: JobState[] }) {
  const [loading, setLoading] = useState<string | null>(null);

  async function handleAction(
    containerName: string,
    action: "pause" | "stop" | "restart" | "unpause",
  ) {
    setLoading(`${containerName}-${action}`);
    try {
      await api.controlWorker(containerName, action);
    } catch {
      // toast shown by api.request()
    } finally {
      setLoading(null);
    }
  }

  if (jobs.length === 0) {
    return (
      <div className="flex h-32 items-center justify-center text-sm text-text-muted">
        No workers active
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {jobs.map((job) => {
        const isLoading = loading?.startsWith(job.container_name);
        return (
          <div
            key={job.id}
            className="flex items-center justify-between rounded-md border border-border bg-bg-tertiary px-4 py-3"
          >
            {/* Left — status + name */}
            <div className="flex items-center gap-3">
              <span
                className={`h-2 w-2 rounded-full ${STATUS_DOT[job.status]}`}
              />
              <Container className="h-4 w-4 text-text-muted" />
              <div>
                <p className="text-sm font-medium text-text-primary">
                  {job.container_name}
                </p>
                <p className="text-xs text-text-muted">
                  {job.current_phase ?? "—"} ·{" "}
                  <span className={STATUS_COLORS[job.status]}>
                    {job.status}
                  </span>
                </p>
              </div>
            </div>

            {/* Right — actions */}
            <div className="flex items-center gap-1">
              {isLoading ? (
                <Loader2 className="h-4 w-4 animate-spin text-accent" />
              ) : (
                actionButtons(job.status).map((btn) => (
                  <button
                    key={btn.action}
                    onClick={() => handleAction(job.container_name, btn.action)}
                    title={btn.label}
                    className={`rounded p-1.5 text-text-muted transition-colors hover:bg-bg-surface ${btn.hoverColor}`}
                  >
                    <btn.icon className="h-3.5 w-3.5" />
                  </button>
                ))
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}
