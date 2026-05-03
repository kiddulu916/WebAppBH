"use client";

import { useRef, useEffect, useState, useMemo } from "react";
import type { SSEEvent } from "@/types/events";

interface LiveTerminalProps {
  events: SSEEvent[];
  collapsed?: boolean;
}

const EVENT_COLORS: Record<string, string> = {
  worker_started: "text-text-primary",
  worker_complete: "text-neon-green",
  worker_failed: "text-danger",
  stage_started: "text-text-muted",
  stage_complete: "text-text-muted",
  finding: "text-warning",
  finding_critical: "text-danger font-bold",
  finding_high: "text-warning",
  escalated_access: "text-danger font-bold",
  target_expanded: "text-neon-blue",
  resource_tier_change: "text-warning",
};

const FILTER_OPTIONS = [
  { label: "All", value: "all" },
  { label: "Findings Only", value: "findings" },
  { label: "Worker Lifecycle", value: "lifecycle" },
  { label: "Errors", value: "errors" },
];

function getEventColor(event: SSEEvent): string {
  const e = event.event as string;
  if (e === "finding" || e === "NEW_ASSET") {
    const sev = (event as Record<string, unknown>).severity as string | undefined;
    if (sev?.toLowerCase() === "critical") return EVENT_COLORS.finding_critical;
    if (sev?.toLowerCase() === "high") return EVENT_COLORS.finding_high;
    return EVENT_COLORS.finding;
  }
  if (e === "escalated_access") return EVENT_COLORS.escalated_access;
  if (e === "target_expanded" || e === "NEW_ASSET") return EVENT_COLORS.target_expanded;
  if (e === "resource_tier_change") return EVENT_COLORS.resource_tier_change;
  if (e === "WORKER_SPAWNED" || e === "worker_started") return EVENT_COLORS.worker_started;
  if (e === "PIPELINE_COMPLETE" || e === "worker_complete") return EVENT_COLORS.worker_complete;
  if (e === "worker_failed") return EVENT_COLORS.worker_failed;
  if (e === "STAGE_COMPLETE" || e === "stage_started" || e === "stage_complete") return EVENT_COLORS.stage_complete;
  return "text-text-secondary";
}

function formatEventLine(event: SSEEvent): string {
  const d = event as Record<string, unknown>;
  const time = event.timestamp ? new Date(event.timestamp).toLocaleTimeString() : "--:--:--";
  const worker = d.worker ? `[${d.worker}]` : "";
  const msg = (d.title as string) || event.event;
  const extra = d.error ? ` - ${d.error}` : d.count !== undefined ? ` (${d.count})` : "";
  return `${time} ${worker} ${msg}${extra}`;
}

function matchesFilter(event: SSEEvent, filter: string): boolean {
  const e = event.event as string;
  const d = event as Record<string, unknown>;
  switch (filter) {
    case "findings":
      return e === "finding" || e === "NEW_ASSET" || d.severity !== undefined;
    case "lifecycle":
      return ["worker_started", "worker_complete", "worker_failed", "worker_queued", "worker_skipped", "WORKER_SPAWNED", "PIPELINE_COMPLETE"].includes(e);
    case "errors":
      return e === "worker_failed" || d.error !== undefined;
    default:
      return true;
  }
}

export default function LiveTerminal({ events, collapsed: initialCollapsed = true }: LiveTerminalProps) {
  const [collapsed, setCollapsed] = useState(initialCollapsed);
  const [filter, setFilter] = useState("all");
  const [autoScroll, setAutoScroll] = useState(true);
  const scrollRef = useRef<HTMLDivElement>(null);

  const filteredEvents = useMemo(() => {
    return events.filter((e) => matchesFilter(e, filter));
  }, [events, filter]);

  useEffect(() => {
    if (autoScroll && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [filteredEvents, autoScroll]);

  return (
    <div className="border-t border-border bg-bg-surface">
      {/* Header */}
      <button
        onClick={() => setCollapsed(!collapsed)}
        className="w-full flex items-center justify-between px-4 py-2 hover:bg-bg-surface/80"
      >
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium text-text-primary">Live Terminal</span>
          <span className="text-xs text-text-secondary">({events.length} events)</span>
        </div>
        <span className="text-text-secondary">{collapsed ? "▲" : "▼"}</span>
      </button>

      {!collapsed && (
        <div className="border-t border-border">
          {/* Controls */}
          <div className="flex items-center gap-4 px-4 py-2 border-b border-border">
            <select
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              className="rounded-md border border-border bg-bg-void px-2 py-1 text-xs text-text-primary"
            >
              {FILTER_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
            <label className="flex items-center gap-1 text-xs text-text-secondary">
              <input
                type="checkbox"
                checked={autoScroll}
                onChange={(e) => setAutoScroll(e.target.checked)}
                className="rounded border-border"
              />
              Auto-scroll
            </label>
            <button
              onClick={() => setCollapsed(true)}
              className="ml-auto text-xs text-text-secondary hover:text-text-primary"
            >
              Clear & Collapse
            </button>
          </div>

          {/* Events */}
          <div
            ref={scrollRef}
            className="h-48 overflow-y-auto p-4 font-mono text-xs space-y-1"
          >
            {filteredEvents.length === 0 ? (
              <div className="text-text-secondary text-center py-4">No events</div>
            ) : (
              filteredEvents.map((event, idx) => (
                <div key={idx} className={getEventColor(event)}>
                  {formatEventLine(event)}
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
}
