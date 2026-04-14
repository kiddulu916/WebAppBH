"use client";

import { useMemo } from "react";
import type { JobState } from "@/types/schema";

const STATUS_COLORS: Record<string, string> = {
  RUNNING: "bg-neon-orange",
  COMPLETED: "bg-neon-green",
  FAILED: "bg-danger",
  PAUSED: "bg-warning",
  QUEUED: "bg-text-muted",
  STOPPED: "bg-text-muted",
  KILLED: "bg-danger",
};

const STATUS_LABEL_COLORS: Record<string, string> = {
  RUNNING: "text-neon-orange",
  COMPLETED: "text-neon-green",
  FAILED: "text-danger",
  PAUSED: "text-warning",
  QUEUED: "text-text-muted",
  STOPPED: "text-text-muted",
  KILLED: "text-danger",
};

function workerLabel(containerName: string): string {
  return containerName
    .replace(/^webbh[-_]/, "")
    .replace(/[-_]\d+$/, "")
    .replace(/[-_]/g, " ");
}

export default function ScanTimeline({ jobs }: { jobs: JobState[] }) {
  const { rows, minTime, maxTime } = useMemo(() => {
    if (jobs.length === 0) return { rows: [], minTime: 0, maxTime: 1 };

    const now = Date.now();

    const parsed = jobs
      .filter((j) => j.started_at || j.created_at)
      .map((j) => {
        const start = new Date(j.started_at || j.created_at!).getTime();
        const end = j.completed_at
          ? new Date(j.completed_at).getTime()
          : j.status === "RUNNING"
            ? now
            : j.last_seen
              ? new Date(j.last_seen).getTime()
              : start + 1000;
        return { ...j, start, end: Math.max(end, start + 1000) };
      })
      .sort((a, b) => a.start - b.start);

    if (parsed.length === 0) return { rows: [], minTime: 0, maxTime: 1 };

    const min = Math.min(...parsed.map((r) => r.start));
    const max = Math.max(...parsed.map((r) => r.end), now);

    return { rows: parsed, minTime: min, maxTime: max };
  }, [jobs]);

  if (rows.length === 0) {
    return (
      <div className="rounded-lg border border-dashed border-border-accent bg-bg-tertiary p-6 text-center text-xs text-text-muted">
        No scan data to display. Launch a scan to see the timeline.
      </div>
    );
  }

  const range = maxTime - minTime || 1;

  function formatDuration(ms: number): string {
    const sec = Math.floor(ms / 1000);
    if (sec < 60) return `${sec}s`;
    const min = Math.floor(sec / 60);
    const remSec = sec % 60;
    return `${min}m ${remSec}s`;
  }

  function formatTime(ts: number): string {
    const d = new Date(ts);
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  }

  return (
    <div className="space-y-3">
      <h3 className="section-label">Scan Timeline</h3>

      {/* Time axis labels */}
      <div className="relative h-4 ml-36 mr-2">
        <span className="absolute left-0 text-[9px] text-text-muted font-mono">
          {formatTime(minTime)}
        </span>
        <span className="absolute right-0 text-[9px] text-text-muted font-mono">
          {formatTime(maxTime)}
        </span>
      </div>

      {/* Rows */}
      <div className="space-y-1">
        {rows.map((row) => {
          const leftPct = ((row.start - minTime) / range) * 100;
          const widthPct = ((row.end - row.start) / range) * 100;
          const barColor = STATUS_COLORS[row.status] || "bg-text-muted";
          const labelColor = STATUS_LABEL_COLORS[row.status] || "text-text-muted";

          return (
            <div key={row.id} className="flex items-center gap-2 group">
              {/* Worker label */}
              <div className="w-36 shrink-0 truncate text-right">
                <span className="font-mono text-[11px] text-text-secondary">
                  {workerLabel(row.container_name)}
                </span>
              </div>

              {/* Bar track */}
              <div className="relative flex-1 h-5 rounded bg-bg-tertiary">
                <div
                  className={`absolute top-0.5 bottom-0.5 rounded ${barColor} ${
                    row.status === "RUNNING" ? "animate-pulse" : ""
                  } transition-all`}
                  style={{
                    left: `${leftPct}%`,
                    width: `${Math.max(widthPct, 0.5)}%`,
                  }}
                />
                {/* Tooltip on hover */}
                <div
                  className="absolute top-0 bottom-0 opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none"
                  style={{
                    left: `${leftPct}%`,
                    width: `${Math.max(widthPct, 0.5)}%`,
                  }}
                >
                  <div className="absolute -top-7 left-1/2 -translate-x-1/2 whitespace-nowrap rounded bg-bg-secondary border border-border px-2 py-0.5 text-[9px] text-text-secondary shadow-lg">
                    {formatDuration(row.end - row.start)} &middot;{" "}
                    {row.current_phase || row.last_completed_stage || "—"}
                  </div>
                </div>
              </div>

              {/* Status badge */}
              <span className={`w-16 shrink-0 text-[9px] font-semibold uppercase ${labelColor}`}>
                {row.status}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
