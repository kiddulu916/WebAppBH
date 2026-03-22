"use client";

import { useMemo } from "react";
import { Clock } from "lucide-react";
import type { JobState } from "@/types/schema";

interface CampaignTimelineProps {
  jobs: JobState[];
}

export default function CampaignTimeline({ jobs }: CampaignTimelineProps) {
  const { entries, timeRange } = useMemo(() => {
    if (jobs.length === 0) return { entries: [], timeRange: { min: 0, max: 1 } };

    const now = Date.now();
    const parsed = jobs
      .filter((j) => j.created_at)
      .map((j) => ({
        container: j.container_name,
        phase: j.current_phase ?? "unknown",
        status: j.status,
        start: new Date(j.created_at).getTime(),
        end: j.last_seen ? new Date(j.last_seen).getTime() : now,
      }));

    if (parsed.length === 0) return { entries: [], timeRange: { min: 0, max: 1 } };

    const min = Math.min(...parsed.map((e) => e.start));
    const max = Math.max(...parsed.map((e) => e.end));

    return {
      entries: parsed,
      timeRange: { min, max: max === min ? max + 1000 : max },
    };
  }, [jobs]);

  if (entries.length === 0) {
    return null;
  }

  const totalMs = timeRange.max - timeRange.min;

  const statusColor: Record<string, string> = {
    RUNNING: "bg-neon-green",
    COMPLETED: "bg-neon-blue",
    FAILED: "bg-danger",
    PAUSED: "bg-neon-orange",
    PENDING: "bg-text-muted",
  };

  const formatTime = (ms: number) => {
    const d = new Date(ms);
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  };

  const formatDuration = (start: number, end: number) => {
    const secs = Math.round((end - start) / 1000);
    if (secs < 60) return `${secs}s`;
    const mins = Math.round(secs / 60);
    if (mins < 60) return `${mins}m`;
    return `${Math.floor(mins / 60)}h ${mins % 60}m`;
  };

  return (
    <div className="rounded-lg border border-border bg-bg-secondary p-4">
      <div className="mb-3 flex items-center gap-2">
        <Clock className="h-4 w-4 text-neon-blue" />
        <span className="section-label">CAMPAIGN TIMELINE</span>
      </div>

      {/* Time axis */}
      <div className="mb-2 flex justify-between text-[10px] font-mono text-text-muted">
        <span>{formatTime(timeRange.min)}</span>
        <span>{formatTime(timeRange.min + totalMs / 2)}</span>
        <span>{formatTime(timeRange.max)}</span>
      </div>

      {/* Gantt bars */}
      <div className="space-y-1.5">
        {entries.map((entry, i) => {
          const left = ((entry.start - timeRange.min) / totalMs) * 100;
          const width = Math.max(
            ((entry.end - entry.start) / totalMs) * 100,
            1,
          );

          return (
            <div key={i} className="flex items-center gap-2">
              <span className="w-28 shrink-0 truncate font-mono text-[10px] text-text-muted">
                {entry.container}
              </span>
              <div className="relative h-5 flex-1 rounded bg-bg-void">
                <div
                  className={`absolute top-0.5 bottom-0.5 rounded ${statusColor[entry.status] ?? "bg-text-muted"} opacity-80`}
                  style={{ left: `${left}%`, width: `${width}%` }}
                  title={`${entry.phase} — ${entry.status} (${formatDuration(entry.start, entry.end)})`}
                />
              </div>
              <span className="w-10 shrink-0 text-right font-mono text-[10px] text-text-muted">
                {formatDuration(entry.start, entry.end)}
              </span>
            </div>
          );
        })}
      </div>

      {/* Legend */}
      <div className="mt-3 flex gap-3">
        {Object.entries(statusColor).map(([status, color]) => (
          <div key={status} className="flex items-center gap-1">
            <span className={`h-2 w-2 rounded-full ${color}`} />
            <span className="text-[10px] text-text-muted">{status}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
