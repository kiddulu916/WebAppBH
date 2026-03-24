"use client";

import { useEffect, useRef } from "react";
import { useCampaignStore } from "@/stores/campaign";
import type { SSEEvent } from "@/types/events";

/**
 * Connects to the orchestrator SSE stream for the active target.
 * Pushes events to the global campaign store — no toasts, no popups.
 * Call once in the layout; all components consume from the store.
 */
export function useEventStream(targetId: number | null) {
  const sourceRef = useRef<EventSource | null>(null);
  const { setConnected, pushEvent, bumpCounter } = useCampaignStore.getState();

  useEffect(() => {
    if (targetId == null) {
      useCampaignStore.getState().setConnected(false);
      return;
    }

    const url = `/api/sse/${targetId}`;
    const es = new EventSource(url);
    sourceRef.current = es;

    es.onopen = () => useCampaignStore.getState().setConnected(true);
    es.onerror = () => useCampaignStore.getState().setConnected(false);

    const handleEvent = (e: MessageEvent) => {
      try {
        const data: SSEEvent = JSON.parse(e.data);
        data.timestamp = new Date().toISOString();

        useCampaignStore.getState().pushEvent(data);

        // Silently bump counters — no toasts
        if (data.event === "NEW_ASSET") {
          useCampaignStore.getState().bumpCounter("assets");
        } else if (data.event === "WORKER_SPAWNED") {
          useCampaignStore.getState().bumpCounter("workers");
        } else if (data.event === "CRITICAL_ALERT" || data.event === "CHAIN_SUCCESS" || data.event === "CLOUD_CREDENTIAL_LEAK") {
          useCampaignStore.getState().incrementUnreadAlerts();
          useCampaignStore.getState().bumpCounter("vulns");
        } else if (data.event === "ACTION_REQUIRED") {
          useCampaignStore.getState().incrementUnreadAlerts();
        }
      } catch {
        // ignore malformed events
      }
    };

    for (const t of [
      "TOOL_PROGRESS",
      "NEW_ASSET",
      "CRITICAL_ALERT",
      "WORKER_SPAWNED",
      "STAGE_COMPLETE",
      "PIPELINE_COMPLETE",
      "RECON_DIFF",
      "SCOPE_DRIFT",
      "AUTOSCALE_RECOMMENDATION",
      "CHAIN_SUCCESS",
      "ACTION_REQUIRED",
      "CLOUD_CREDENTIAL_LEAK",
      "REPORT_FORMAT_COMPLETE",
      "REPORT_COMPLETE",
      "KILL_ALL",
      "RERUN_STARTED",
      "CLEAN_SLATE",
    ]) {
      es.addEventListener(t, handleEvent);
    }
    es.onmessage = handleEvent;

    return () => {
      es.close();
      sourceRef.current = null;
    };
  }, [targetId]);
}
