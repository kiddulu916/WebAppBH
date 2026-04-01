import { useState, useEffect } from "react";
import type { TargetEvent } from "@/types/campaign";
import { usePipelineStore } from "@/stores/pipelineStore";

export function useTargetEvents(targetId: number) {
  const [events, setEvents] = useState<TargetEvent[]>([]);
  const updateFromEvent = usePipelineStore((s) => s.updateFromEvent);

  useEffect(() => {
    const source = new EventSource(`/api/sse/${targetId}`);

    source.onmessage = (event) => {
      const data: TargetEvent = JSON.parse(event.data);
      setEvents((prev) => [...prev.slice(-500), data]);
      updateFromEvent(data);
    };

    return () => source.close();
  }, [targetId, updateFromEvent]);

  return events;
}
