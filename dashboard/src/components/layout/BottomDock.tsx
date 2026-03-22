"use client";

import { useRef, useEffect, useState } from "react";
import { Terminal, ChevronUp, ChevronDown, Filter, X } from "lucide-react";
import { useCampaignStore } from "@/stores/campaign";
import { useUIStore } from "@/stores/ui";
import type { SSEEvent, SSEEventType } from "@/types/events";

const EVENT_COLORS: Record<string, string> = {
  WORKER_SPAWNED: "text-neon-green",
  TOOL_PROGRESS: "text-neon-blue",
  NEW_ASSET: "text-neon-blue",
  CRITICAL_ALERT: "text-danger",
  RECON_DIFF: "text-neon-orange",
  SCOPE_DRIFT: "text-warning",
  AUTOSCALE_RECOMMENDATION: "text-text-muted",
};

const EVENT_TYPES: SSEEventType[] = [
  "TOOL_PROGRESS",
  "NEW_ASSET",
  "WORKER_SPAWNED",
  "CRITICAL_ALERT",
  "RECON_DIFF",
  "SCOPE_DRIFT",
  "AUTOSCALE_RECOMMENDATION",
];

export default function BottomDock() {
  const events = useCampaignStore((s) => s.events);
  const { dockExpanded, toggleDock } = useUIStore();
  const bottomRef = useRef<HTMLDivElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);
  const [filterType, setFilterType] = useState<SSEEventType | null>(null);
  const [showFilters, setShowFilters] = useState(false);

  const filteredEvents = filterType
    ? events.filter((e) => e.event === filterType)
    : events;

  // Auto-scroll when new events arrive (only if user hasn't scrolled up)
  useEffect(() => {
    if (autoScroll && dockExpanded) {
      bottomRef.current?.scrollIntoView({ behavior: "smooth" });
    }
  }, [filteredEvents.length, autoScroll, dockExpanded]);

  function handleScroll() {
    const el = containerRef.current;
    if (!el) return;
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
    setAutoScroll(atBottom);
  }

  // Preview: show last 3 events when collapsed
  const previewEvents = filteredEvents.slice(-3);

  return (
    <div className="border-t border-border bg-bg-primary">
      {/* Header bar */}
      <button
        onClick={toggleDock}
        className="flex w-full items-center gap-2 px-3 py-1 text-xs hover:bg-bg-secondary transition-colors"
      >
        <Terminal className="h-3 w-3 text-neon-green" />
        <span className="section-label">Live Feed</span>
        <span className="ml-1 text-text-muted font-mono">
          {events.length}
        </span>
        <div className="ml-auto flex items-center gap-1">
          {filterType && (
            <span className="rounded bg-neon-orange-glow px-1.5 py-0.5 text-[9px] text-neon-orange">
              {filterType}
            </span>
          )}
          {dockExpanded ? (
            <ChevronDown className="h-3 w-3 text-text-muted" />
          ) : (
            <ChevronUp className="h-3 w-3 text-text-muted" />
          )}
        </div>
      </button>

      {/* Collapsed preview */}
      {!dockExpanded && previewEvents.length > 0 && (
        <div className="border-t border-border px-3 py-0.5 terminal-text">
          {previewEvents.map((evt, i) => (
            <EventLine key={events.length - 3 + i} evt={evt} compact />
          ))}
        </div>
      )}

      {/* Expanded view */}
      {dockExpanded && (
        <>
          {/* Filter bar */}
          {showFilters && (
            <div className="flex items-center gap-1 border-t border-border px-3 py-1 animate-fade-in">
              <button
                onClick={() => { setFilterType(null); setShowFilters(false); }}
                className={`rounded px-1.5 py-0.5 text-[9px] transition-colors ${
                  !filterType ? "bg-neon-orange-glow text-neon-orange" : "text-text-muted hover:text-text-secondary"
                }`}
              >
                All
              </button>
              {EVENT_TYPES.map((t) => (
                <button
                  key={t}
                  onClick={() => setFilterType(t)}
                  className={`rounded px-1.5 py-0.5 text-[9px] transition-colors ${
                    filterType === t ? "bg-neon-orange-glow text-neon-orange" : "text-text-muted hover:text-text-secondary"
                  }`}
                >
                  {t.replace(/_/g, " ")}
                </button>
              ))}
            </div>
          )}

          {/* Action buttons */}
          <div className="flex items-center gap-1 border-t border-border px-3 py-0.5">
            <button
              onClick={() => setShowFilters(!showFilters)}
              className="flex items-center gap-1 rounded px-1.5 py-0.5 text-[9px] text-text-muted hover:text-text-secondary transition-colors"
            >
              <Filter className="h-2.5 w-2.5" />
              Filter
            </button>
            {filterType && (
              <button
                onClick={() => setFilterType(null)}
                className="flex items-center gap-0.5 rounded px-1.5 py-0.5 text-[9px] text-neon-orange hover:text-neon-orange-dim transition-colors"
              >
                <X className="h-2.5 w-2.5" />
                Clear
              </button>
            )}
            <span className="ml-auto text-[9px] text-text-muted">
              {autoScroll ? "auto-scroll" : "scroll-locked"}
            </span>
          </div>

          {/* Event log */}
          <div
            ref={containerRef}
            onScroll={handleScroll}
            className="h-48 overflow-y-auto px-3 py-1 terminal-text"
          >
            {filteredEvents.length === 0 ? (
              <p className="text-text-muted py-2">Waiting for events...</p>
            ) : (
              filteredEvents.map((evt, i) => (
                <EventLine key={i} evt={evt} />
              ))
            )}
            <div ref={bottomRef} />
          </div>
        </>
      )}
    </div>
  );
}

function EventLine({ evt, compact }: { evt: SSEEvent; compact?: boolean }) {
  const d = evt as Record<string, unknown>;
  const color = EVENT_COLORS[evt.event] ?? "text-text-muted";
  const time = evt.timestamp
    ? new Date(evt.timestamp).toLocaleTimeString("en-US", { hour12: false })
    : "--:--:--";

  return (
    <div className={`flex gap-2 ${compact ? "opacity-60" : ""}`}>
      <span className="shrink-0 text-text-muted">{time}</span>
      <span className={`shrink-0 ${color}`}>[{evt.event}]</span>
      <span className="text-text-secondary truncate">
        {formatEvent(evt, d)}
      </span>
    </div>
  );
}

function formatEvent(evt: SSEEvent, d: Record<string, unknown>): string {
  switch (evt.event) {
    case "WORKER_SPAWNED":
      return `${d.container ?? "?"} started (${d.phase ?? ""})`;
    case "TOOL_PROGRESS":
      return `${d.tool ?? "?"}: ${d.message ?? ""} (${d.progress ?? 0}%)`;
    case "NEW_ASSET":
      return `${d.asset_type ?? "?"}: ${d.asset_value ?? "?"}`;
    case "CRITICAL_ALERT":
      return `${d.alert_type ?? "Alert"}: ${d.message ?? ""}`;
    case "RECON_DIFF":
      return `Scan #${d.scan_number ?? "?"}: +${(d.added as string[])?.length ?? 0} -${(d.removed as string[])?.length ?? 0}`;
    case "SCOPE_DRIFT":
      return `${d.asset_value ?? "?"} (${d.classification ?? "unknown"})`;
    case "AUTOSCALE_RECOMMENDATION":
      return `${d.queue ?? "?"}: ${d.action ?? ""} (${d.pending ?? 0} pending)`;
    default:
      return JSON.stringify(d);
  }
}
