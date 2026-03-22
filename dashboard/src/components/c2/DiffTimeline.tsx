"use client";

import { Plus, Minus, Clock } from "lucide-react";
import type { SSEEvent } from "@/types/events";

interface DiffTimelineProps {
  events: SSEEvent[];
}

export default function DiffTimeline({ events }: DiffTimelineProps) {
  const diffs = events.filter((e) => e.event === "RECON_DIFF");

  if (diffs.length === 0) {
    return (
      <div className="rounded-lg border border-border bg-bg-secondary p-4">
        <p className="text-sm text-text-muted">No recon diffs yet. Trigger a rescan to see changes.</p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <h3 className="text-sm font-semibold text-text-primary">Recon Diff Timeline</h3>
      <div className="space-y-2">
        {diffs.map((d, i) => {
          const added = (d as Record<string, unknown>).added as string[] | undefined;
          const removed = (d as Record<string, unknown>).removed as string[] | undefined;
          const scanNum = (d as Record<string, unknown>).scan_number as number;
          const ts = d.timestamp;

          return (
            <div key={i} className="rounded-lg border border-border bg-bg-secondary p-3">
              <div className="flex items-center gap-2 text-xs text-text-muted">
                <Clock className="h-3 w-3" />
                <span>Scan #{scanNum}</span>
                {ts && <span>· {new Date(ts).toLocaleTimeString()}</span>}
              </div>
              {added && added.length > 0 && (
                <div className="mt-2 space-y-1">
                  {added.map((a) => (
                    <div key={a} className="flex items-center gap-1 text-xs text-green-400">
                      <Plus className="h-3 w-3" />
                      <span className="font-mono">{a}</span>
                    </div>
                  ))}
                </div>
              )}
              {removed && removed.length > 0 && (
                <div className="mt-2 space-y-1">
                  {removed.map((r) => (
                    <div key={r} className="flex items-center gap-1 text-xs text-red-400">
                      <Minus className="h-3 w-3" />
                      <span className="font-mono">{r}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
