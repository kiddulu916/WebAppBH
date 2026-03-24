"use client";

import { useRef, useEffect } from "react";
import { Terminal } from "lucide-react";
import type { SSEEvent } from "@/types/events";

export default function WorkerFeed({ events }: { events: SSEEvent[] }) {
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [events.length]);

  return (
    <div className="flex flex-col rounded-lg border border-border bg-bg-tertiary">
      {/* Header */}
      <div className="flex items-center gap-2 border-b border-border px-3 py-2">
        <Terminal className="h-3.5 w-3.5 text-accent" />
        <span className="text-xs font-medium text-text-secondary">
          Worker Feed
        </span>
        <span className="ml-auto text-xs text-text-muted">
          {events.length} events
        </span>
      </div>

      {/* Scrollable log */}
      <div className="h-64 overflow-y-auto px-3 py-2 font-mono text-xs leading-5">
        {events.length === 0 ? (
          <p className="text-text-muted">Waiting for events...</p>
        ) : (
          events.map((evt, i) => (
            <div key={i} className="flex gap-2">
              <span className="shrink-0 text-text-muted">
                {evt.timestamp
                  ? new Date(evt.timestamp).toLocaleTimeString()
                  : "—"}
              </span>
              <span className={eventColor(evt.event)}>
                [{evt.event}]
              </span>
              <span className="text-text-secondary">
                {formatEvent(evt)}
              </span>
            </div>
          ))
        )}
        <div ref={bottomRef} />
      </div>
    </div>
  );
}

function eventColor(type: string): string {
  switch (type) {
    case "WORKER_SPAWNED":     return "text-success";
    case "TOOL_PROGRESS":      return "text-accent";
    case "NEW_ASSET":          return "text-info";
    case "CRITICAL_ALERT":     return "text-danger";
    case "STAGE_COMPLETE":     return "text-neon-green";
    case "PIPELINE_COMPLETE":  return "text-neon-green";
    case "CHAIN_SUCCESS":      return "text-neon-orange";
    case "ACTION_REQUIRED":    return "text-warning";
    case "CLOUD_CREDENTIAL_LEAK": return "text-danger";
    default:                   return "text-text-muted";
  }
}

function formatEvent(evt: SSEEvent): string {
  const d = evt as Record<string, unknown>;
  switch (evt.event) {
    case "WORKER_SPAWNED":
      return `Container ${d.container ?? "?"} started (${d.phase ?? ""})`;
    case "TOOL_PROGRESS":
      return `${d.tool ?? "?"}: ${d.message ?? ""} (${d.progress ?? 0}%)`;
    case "NEW_ASSET":
      return `${d.asset_type ?? "?"}: ${d.asset_value ?? "?"}`;
    case "CRITICAL_ALERT":
      return `${d.alert_type ?? "Alert"}: ${d.message ?? ""}`;
    case "STAGE_COMPLETE":
      return `Stage ${d.stage ?? "?"} complete`;
    case "PIPELINE_COMPLETE":
      return `Pipeline finished`;
    case "CHAIN_SUCCESS":
      return `Chain ${d.chain ?? "?"} succeeded (${d.severity ?? "?"})`;
    case "ACTION_REQUIRED":
      return `${d.message ?? "Action required"}`;
    case "REPORT_COMPLETE":
      return `Report ready: ${(d.formats as string[])?.join(", ") ?? "?"}`;
    default:
      return JSON.stringify(d);
  }
}
