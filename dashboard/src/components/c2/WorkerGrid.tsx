"use client";

import { useMemo } from "react";
import { Users } from "lucide-react";
import WorkerCard from "@/components/c2/WorkerCard";
import type { JobState } from "@/types/schema";
import type { SSEEvent, ToolProgressEvent } from "@/types/events";

interface WorkerGridProps {
  jobs: JobState[];
  events: SSEEvent[];
  onRefresh?: () => void;
}

interface WorkerProgress {
  progress: number;
  discoveredCount: number;
}

export default function WorkerGrid({ jobs, events, onRefresh }: WorkerGridProps) {
  // Extract latest progress info per container from TOOL_PROGRESS events
  const progressMap = useMemo(() => {
    const map = new Map<string, WorkerProgress>();

    for (const evt of events) {
      if (evt.event !== "TOOL_PROGRESS") continue;
      const tp = evt as ToolProgressEvent;
      const existing = map.get(tp.container);
      if (existing) {
        // Keep the highest progress value
        if (tp.progress > existing.progress) {
          existing.progress = tp.progress;
        }
      } else {
        map.set(tp.container, {
          progress: tp.progress,
          discoveredCount: 0,
        });
      }
    }

    // Count NEW_ASSET events per container (from TOOL_PROGRESS container association)
    // Since NEW_ASSET events don't have container info, we count overall discovered assets
    let totalDiscovered = 0;
    for (const evt of events) {
      if (evt.event === "NEW_ASSET") totalDiscovered++;
    }

    // Distribute discovered count proportionally (or evenly among running workers)
    const runningContainers = jobs
      .filter((j) => j.status === "RUNNING")
      .map((j) => j.container_name);

    if (runningContainers.length > 0 && totalDiscovered > 0) {
      const perWorker = Math.floor(totalDiscovered / runningContainers.length);
      for (const name of runningContainers) {
        const existing = map.get(name);
        if (existing) {
          existing.discoveredCount = perWorker;
        } else {
          map.set(name, { progress: 0, discoveredCount: perWorker });
        }
      }
    }

    return map;
  }, [events, jobs]);

  const running = jobs.filter((j) => j.status === "RUNNING").length;
  const queued = jobs.filter((j) => j.status === "QUEUED").length;
  const done = jobs.filter(
    (j) =>
      j.status === "COMPLETED" ||
      j.status === "FAILED" ||
      j.status === "STOPPED",
  ).length;
  const paused = jobs.filter((j) => j.status === "PAUSED").length;

  // Determine current phase from the first running job
  const currentPhase = jobs.find((j) => j.status === "RUNNING")?.current_phase;

  return (
    <div className="space-y-3">
      {/* Summary header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Users className="h-4 w-4 text-neon-blue" />
          <span className="section-label">
            {currentPhase ? `${currentPhase} WORKERS` : "WORKERS"}
          </span>
        </div>
        <div className="flex items-center gap-3 font-mono text-[10px]">
          {running > 0 && (
            <span className="text-neon-green">
              {running} running
            </span>
          )}
          {queued > 0 && (
            <span className="text-neon-orange">
              {queued} queued
            </span>
          )}
          {paused > 0 && (
            <span className="text-warning">
              {paused} paused
            </span>
          )}
          {done > 0 && (
            <span className="text-text-muted">
              {done} done
            </span>
          )}
        </div>
      </div>

      {/* Worker cards grid */}
      {jobs.length === 0 ? (
        <div className="flex h-32 items-center justify-center rounded-lg border border-border bg-bg-secondary text-sm text-text-muted">
          No workers active
        </div>
      ) : (
        <div className="grid grid-cols-4 gap-3">
          {jobs.map((job) => {
            const wp = progressMap.get(job.container_name);
            return (
              <WorkerCard
                key={job.id}
                job={job}
                progress={wp?.progress}
                discoveredCount={wp?.discoveredCount}
                onActionComplete={onRefresh}
              />
            );
          })}
        </div>
      )}
    </div>
  );
}
