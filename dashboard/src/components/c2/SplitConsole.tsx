"use client";

import { useState, useMemo, useRef, useEffect } from "react";
import { X } from "lucide-react";
import type { JobState } from "@/types/schema";
import type { SSEEvent } from "@/types/events";

interface SplitConsoleProps {
  events: SSEEvent[];
  jobs: JobState[];
}

export default function SplitConsole({ events, jobs }: SplitConsoleProps) {
  const containers = useMemo(
    () => [...new Set(jobs.map((j) => j.container_name))],
    [jobs],
  );

  const [selected, setSelected] = useState<string[]>(() =>
    containers.slice(0, 2),
  );

  // Sync initial selection when containers first appear
  useEffect(() => {
    if (selected.length === 0 && containers.length > 0) {
      queueMicrotask(() => setSelected(containers.slice(0, 2)));
    }
  }, [containers, selected.length]);

  const toggle = (name: string) => {
    setSelected((prev) =>
      prev.includes(name)
        ? prev.filter((n) => n !== name)
        : prev.length < 4
          ? [...prev, name]
          : prev,
    );
  };

  return (
    <div className="space-y-3">
      {/* Worker selector chips */}
      <div className="flex flex-wrap gap-1.5">
        {containers.map((name) => {
          const active = selected.includes(name);
          return (
            <button
              key={name}
              onClick={() => toggle(name)}
              className={`rounded-md border px-2 py-1 font-mono text-xs transition-colors ${
                active
                  ? "border-neon-blue/40 bg-neon-blue/10 text-neon-blue"
                  : "border-border bg-bg-surface text-text-muted hover:text-text-secondary"
              }`}
            >
              {name}
            </button>
          );
        })}
      </div>

      {/* Split panes */}
      {selected.length > 0 && (
        <div
          className={`grid gap-3 ${
            selected.length === 1
              ? "grid-cols-1"
              : selected.length === 2
                ? "grid-cols-2"
                : selected.length === 3
                  ? "grid-cols-3"
                  : "grid-cols-2 grid-rows-2"
          }`}
        >
          {selected.map((name) => (
            <WorkerPane
              key={name}
              containerName={name}
              events={events}
              job={jobs.find((j) => j.container_name === name)}
              onClose={() => setSelected((p) => p.filter((n) => n !== name))}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function WorkerPane({
  containerName,
  events,
  job,
  onClose,
}: {
  containerName: string;
  events: SSEEvent[];
  job?: JobState;
  onClose: () => void;
}) {
  const scrollRef = useRef<HTMLDivElement>(null);

  const filtered = useMemo(
    () =>
      events.filter(
        (e) =>
          (e as Record<string, unknown>).container_name === containerName ||
          (e as Record<string, unknown>).source === containerName,
      ),
    [events, containerName],
  );

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [filtered.length]);

  const statusColor =
    job?.status === "RUNNING"
      ? "text-neon-green"
      : job?.status === "COMPLETED"
        ? "text-neon-blue"
        : job?.status === "FAILED"
          ? "text-danger"
          : "text-text-muted";

  return (
    <div className="flex flex-col rounded-lg border border-border bg-bg-void">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-border px-3 py-1.5">
        <div className="flex items-center gap-2">
          <span
            className={`h-2 w-2 rounded-full ${
              job?.status === "RUNNING"
                ? "bg-neon-green animate-pulse"
                : "bg-text-muted"
            }`}
          />
          <span className="font-mono text-xs text-text-primary">
            {containerName}
          </span>
          {job?.current_phase && (
            <span className="rounded bg-bg-surface px-1.5 py-0.5 text-[10px] text-text-muted">
              {job.current_phase}
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <span className={`text-[10px] font-mono ${statusColor}`}>
            {job?.status ?? "UNKNOWN"}
          </span>
          <button
            onClick={onClose}
            className="text-text-muted hover:text-text-primary"
          >
            <X className="h-3 w-3" />
          </button>
        </div>
      </div>

      {/* Terminal output */}
      <div
        ref={scrollRef}
        className="h-64 overflow-y-auto p-2 font-mono text-[11px] leading-relaxed text-text-code"
      >
        {filtered.length === 0 ? (
          <p className="text-text-muted">No events for this worker yet...</p>
        ) : (
          filtered.map((evt, i) => (
            <div key={i} className="flex gap-2">
              <span className="shrink-0 text-text-muted">
                {evt.timestamp
                  ? new Date(evt.timestamp).toLocaleTimeString()
                  : "\u2014"}
              </span>
              <span
                className={
                  evt.event === "CRITICAL_ALERT"
                    ? "text-danger"
                    : evt.event === "NEW_ASSET"
                      ? "text-neon-green"
                      : evt.event === "TOOL_PROGRESS"
                        ? "text-neon-blue"
                        : "text-text-secondary"
                }
              >
                [{evt.event}]
              </span>
              <span className="text-text-primary">
                {String(
                  (evt as Record<string, unknown>).message ??
                    (evt as Record<string, unknown>).asset_value ??
                    JSON.stringify(evt),
                )}
              </span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
