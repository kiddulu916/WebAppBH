"use client";

import { useRef, useEffect, useState, useMemo } from "react";
import type { TargetEvent } from "@/types/campaign";

interface LiveTerminalProps {
  events: TargetEvent[];
  collapsed?: boolean;
}

const EVENT_COLORS: Record<string, string> = {
  worker_started: "text-white",
  worker_complete: "text-green-400",
  worker_failed: "text-red-400",
  stage_started: "text-gray-400",
  stage_complete: "text-gray-400",
  finding: "text-yellow-400",
  finding_critical: "text-red-400 font-bold",
  finding_high: "text-yellow-400",
  escalated_access: "text-red-400 font-bold",
  target_expanded: "text-blue-400",
  resource_tier_change: "text-yellow-400",
};

const FILTER_OPTIONS = [
  { label: "All", value: "all" },
  { label: "Findings Only", value: "findings" },
  { label: "Worker Lifecycle", value: "lifecycle" },
  { label: "Errors", value: "errors" },
];

function getEventColor(event: TargetEvent): string {
  if (event.event === "finding" || event.event === "NEW_ASSET") {
    const sev = event.severity?.toLowerCase();
    if (sev === "critical") return EVENT_COLORS.finding_critical;
    if (sev === "high") return EVENT_COLORS.finding_high;
    return EVENT_COLORS.finding;
  }
  if (event.event === "escalated_access") return EVENT_COLORS.escalated_access;
  if (event.event === "target_expanded" || event.event === "NEW_ASSET") return EVENT_COLORS.target_expanded;
  if (event.event === "resource_tier_change") return EVENT_COLORS.resource_tier_change;
  if (event.event === "worker_started") return EVENT_COLORS.worker_started;
  if (event.event === "worker_complete") return EVENT_COLORS.worker_complete;
  if (event.event === "worker_failed") return EVENT_COLORS.worker_failed;
  if (event.event === "stage_started" || event.event === "stage_complete") return EVENT_COLORS.stage_complete;
  return "text-text-secondary";
}

function formatEventLine(event: TargetEvent): string {
  const time = event.timestamp ? new Date(event.timestamp).toLocaleTimeString() : "--:--:--";
  const worker = event.worker ? `[${event.worker}]` : "";
  const msg = event.title || event.event;
  const extra = event.error ? ` - ${event.error}` : event.count !== undefined ? ` (${event.count})` : "";
  return `${time} ${worker} ${msg}${extra}`;
}

function matchesFilter(event: TargetEvent, filter: string): boolean {
  switch (filter) {
    case "findings":
      return event.event === "finding" || event.event === "NEW_ASSET" || event.severity !== undefined;
    case "lifecycle":
      return ["worker_started", "worker_complete", "worker_failed", "worker_queued", "worker_skipped"].includes(event.event);
    case "errors":
      return event.event === "worker_failed" || event.error !== undefined;
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
