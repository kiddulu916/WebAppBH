"use client";

import { Cpu } from "lucide-react";
import type { JobState } from "@/types/schema";

export default function StatusBoard({ jobs }: { jobs: JobState[] }) {
  const running = jobs.filter((j) => j.status === "RUNNING");

  if (running.length === 0) return null;

  return (
    <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-4">
      {running.map((job) => (
        <div
          key={job.id}
          className="flex items-center gap-3 rounded-md border border-border bg-bg-secondary px-3 py-2"
        >
          <span className="relative flex h-2 w-2">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-success opacity-75" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-success" />
          </span>
          <Cpu className="h-3.5 w-3.5 text-text-muted" />
          <div className="min-w-0">
            <p className="truncate text-xs font-medium text-text-primary">
              {job.container_name}
            </p>
            <p className="text-[10px] text-text-muted">
              {job.current_phase ?? "\u2014"}
              {job.last_tool_executed && (
                <span className="ml-1 rounded bg-accent/10 px-1 text-accent">
                  {job.last_tool_executed}
                </span>
              )}
            </p>
          </div>
        </div>
      ))}
    </div>
  );
}
