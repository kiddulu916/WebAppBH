import { useState, useEffect } from "react";
import type { SSEEvent } from "@/types/events";
import { useCampaignStore } from "@/stores/campaign";

export function useTargetEvents(targetId: number) {
  const [events, setEvents] = useState<SSEEvent[]>([]);
  const updateFromEvent = useCampaignStore((s) => s.updateFromEvent);

  useEffect(() => {
    const source = new EventSource(`/api/sse/${targetId}`);

    source.onmessage = (event) => {
      const data: SSEEvent = JSON.parse(event.data);
      setEvents((prev) => [...prev.slice(-500), data]);
      updateFromEvent(data);
    };

    return () => source.close();
  }, [targetId, updateFromEvent]);

  return events;
}
