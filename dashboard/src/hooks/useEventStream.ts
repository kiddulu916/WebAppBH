"use client";

import { useEffect, useRef, useCallback, useState } from "react";
import { toast } from "sonner";
import { useCampaignStore } from "@/stores/campaign";
import type { SSEEvent } from "@/types/events";

/**
 * Hook that connects to the orchestrator SSE stream for a given target.
 * Dispatches events to the campaign store and shows toast alerts.
 */
export function useEventStream(targetId: number | null) {
  const [events, setEvents] = useState<SSEEvent[]>([]);
  const sourceRef = useRef<EventSource | null>(null);
  const setConnected = useCampaignStore((s) => s.setConnected);

  const addEvent = useCallback((evt: SSEEvent) => {
    setEvents((prev) => [...prev.slice(-199), evt]); // keep last 200
  }, []);

  useEffect(() => {
    if (targetId == null) return;

    const url = `/api/sse/${targetId}`;
    const es = new EventSource(url);
    sourceRef.current = es;

    es.onopen = () => setConnected(true);
    es.onerror = () => setConnected(false);

    const handleEvent = (e: MessageEvent) => {
      try {
        const data: SSEEvent = JSON.parse(e.data);
        data.timestamp = new Date().toISOString();
        addEvent(data);

        if (data.event === "CRITICAL_ALERT") {
          toast.error(String((data as Record<string, unknown>).message ?? "Critical alert"), {
            description: String((data as Record<string, unknown>).alert_type ?? ""),
            duration: 10_000,
          });
        } else if (data.event === "WORKER_SPAWNED") {
          toast.info(
            `Worker started: ${String((data as Record<string, unknown>).container ?? "")}`,
            { duration: 4_000 },
          );
        }
      } catch {
        // ignore malformed events
      }
    };

    // Listen for typed events
    for (const t of ["TOOL_PROGRESS", "NEW_ASSET", "CRITICAL_ALERT", "WORKER_SPAWNED"]) {
      es.addEventListener(t, handleEvent);
    }
    // Also listen for generic "message" events
    es.onmessage = handleEvent;

    return () => {
      es.close();
      sourceRef.current = null;
    };
  }, [targetId, addEvent, setConnected]);

  return { events };
}
