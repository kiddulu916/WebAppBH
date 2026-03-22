"use client";

import { AlertTriangle, Shield } from "lucide-react";
import type { SSEEvent } from "@/types/events";

interface ScopeDriftAlertsProps {
  events: SSEEvent[];
}

export default function ScopeDriftAlerts({ events }: ScopeDriftAlertsProps) {
  const drifts = events.filter((e) => e.event === "SCOPE_DRIFT");

  if (drifts.length === 0) {
    return null;
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2">
        <Shield className="h-4 w-4 text-yellow-400" />
        <span className="text-sm font-semibold text-text-primary">
          Scope Drift Detected ({drifts.length})
        </span>
      </div>
      <div className="space-y-1">
        {drifts.slice(-10).map((d, i) => {
          const data = d as Record<string, unknown>;
          return (
            <div
              key={i}
              className="flex items-center gap-2 rounded border border-yellow-500/30 bg-yellow-500/5 px-3 py-2"
            >
              <AlertTriangle className="h-3 w-3 shrink-0 text-yellow-400" />
              <span className="font-mono text-xs text-text-secondary">
                {String(data.asset_value ?? "")}
              </span>
              <span className="text-[10px] text-text-muted">
                {String(data.classification ?? "")}
                {data.provider ? ` · ${String(data.provider)}` : ""}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
