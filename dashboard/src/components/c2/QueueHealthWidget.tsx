"use client";

import { useEffect, useState } from "react";
import { Activity, Loader2 } from "lucide-react";
import { api } from "@/lib/api";

interface QueueStatus {
  pending: number;
  health: string;
}

const HEALTH_COLORS: Record<string, string> = {
  idle: "text-gray-400",
  healthy: "text-green-400",
  pressure: "text-yellow-400",
  critical: "text-red-400",
};

const HEALTH_BG: Record<string, string> = {
  idle: "bg-gray-500/10",
  healthy: "bg-green-500/10",
  pressure: "bg-yellow-500/10",
  critical: "bg-red-500/10",
};

export default function QueueHealthWidget() {
  const [queues, setQueues] = useState<Record<string, QueueStatus>>({});
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    const poll = async () => {
      try {
        const res = await api.getQueueHealth();
        if (mounted) setQueues(res.queues);
      } catch {
        // ignore
      } finally {
        if (mounted) setLoading(false);
      }
    };
    poll();
    const interval = setInterval(poll, 15_000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  if (loading) {
    return (
      <div className="flex h-32 items-center justify-center">
        <Loader2 className="h-4 w-4 animate-spin text-accent" />
      </div>
    );
  }

  const entries = Object.entries(queues);
  if (entries.length === 0) return null;

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2">
        <Activity className="h-4 w-4 text-accent" />
        <span className="text-sm font-semibold text-text-primary">Queue Health</span>
      </div>
      <div className="grid grid-cols-3 gap-2">
        {entries.map(([name, status]) => {
          const label = name.replace("_queue", "").replace("_", " ");
          return (
            <div
              key={name}
              className={`rounded-lg border border-border p-3 ${HEALTH_BG[status.health] || ""}`}
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium capitalize text-text-primary">{label}</span>
                <span
                  className={`text-[10px] font-bold uppercase ${
                    HEALTH_COLORS[status.health] || "text-text-muted"
                  }`}
                >
                  {status.health}
                </span>
              </div>
              <p className="mt-1 text-lg font-bold text-text-primary">{status.pending}</p>
              <p className="text-[10px] text-text-muted">pending messages</p>
            </div>
          );
        })}
      </div>
    </div>
  );
}
