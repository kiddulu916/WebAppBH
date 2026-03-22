"use client";

import { useEffect, useState, useCallback } from "react";
import {
  Activity,
  Database,
  Loader2,
  Server,
  Gauge,
} from "lucide-react";
import { api } from "@/lib/api";
import { useCampaignStore } from "@/stores/campaign";
import { useUIStore } from "@/stores/ui";

interface QueueStatus {
  pending: number;
  health: string;
}

const QUEUE_NAMES = [
  "recon_queue",
  "fuzzing_queue",
  "cloud_queue",
  "api_queue",
] as const;

const QUEUE_LABELS: Record<string, string> = {
  recon_queue: "Recon",
  fuzzing_queue: "Fuzzing",
  cloud_queue: "Cloud",
  api_queue: "API",
};

const HEALTH_DOT: Record<string, string> = {
  idle: "bg-text-muted",
  healthy: "bg-neon-green",
  pressure: "bg-warning",
  critical: "bg-danger",
};

const HEALTH_BAR: Record<string, string> = {
  idle: "bg-text-muted/30",
  healthy: "bg-neon-green",
  pressure: "bg-warning",
  critical: "bg-danger",
};

export default function SystemPulse() {
  const systemPulseOpen = useUIStore((s) => s.systemPulseOpen);
  const counters = useCampaignStore((s) => s.counters);
  const jobs = useCampaignStore((s) => s.jobs);

  const [queues, setQueues] = useState<Record<string, QueueStatus>>({});
  const [loading, setLoading] = useState(true);

  const fetchHealth = useCallback(async () => {
    try {
      const res = await api.getQueueHealth();
      setQueues(res.queues);
    } catch {
      /* ignore */
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!systemPulseOpen) return;

    fetchHealth();
    const interval = setInterval(fetchHealth, 10_000);
    return () => clearInterval(interval);
  }, [systemPulseOpen, fetchHealth]);

  if (!systemPulseOpen) return null;

  const runningWorkers = jobs.filter((j) => j.status === "RUNNING").length;
  const totalWorkers = jobs.length;

  // Find max pending for bar scaling
  const maxPending = Math.max(
    ...QUEUE_NAMES.map((q) => queues[q]?.pending ?? 0),
    1,
  );

  return (
    <div className="animate-fade-in rounded-lg border border-border bg-bg-secondary p-4">
      <div className="section-label mb-4 flex items-center gap-2">
        <Activity className="h-3.5 w-3.5 text-neon-orange" />
        SYSTEM PULSE
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Redis Queue Depths */}
        <div className="space-y-3">
          <div className="flex items-center gap-1.5 text-xs font-medium text-text-secondary">
            <Server className="h-3 w-3" />
            Redis Queues
          </div>
          {loading ? (
            <div className="flex h-20 items-center justify-center">
              <Loader2 className="h-4 w-4 animate-spin text-accent" />
            </div>
          ) : (
            <div className="space-y-2.5">
              {QUEUE_NAMES.map((qName) => {
                const q = queues[qName];
                const pending = q?.pending ?? 0;
                const health = q?.health ?? "idle";
                const barWidth =
                  maxPending > 0
                    ? Math.max((pending / maxPending) * 100, 2)
                    : 2;

                return (
                  <div key={qName}>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-1.5">
                        <span
                          className={`h-1.5 w-1.5 rounded-full ${HEALTH_DOT[health] ?? "bg-text-muted"}`}
                        />
                        <span className="font-mono text-[10px] text-text-secondary">
                          {QUEUE_LABELS[qName]}
                        </span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-[10px] text-text-primary">
                          {pending}
                        </span>
                        <span
                          className={`text-[9px] font-semibold uppercase ${
                            health === "critical"
                              ? "text-danger"
                              : health === "pressure"
                                ? "text-warning"
                                : health === "healthy"
                                  ? "text-neon-green"
                                  : "text-text-muted"
                          }`}
                        >
                          {health}
                        </span>
                      </div>
                    </div>
                    <div className="mt-1 h-1 rounded-full bg-bg-tertiary">
                      <div
                        className={`h-full rounded-full transition-all duration-500 ${HEALTH_BAR[health] ?? "bg-text-muted/30"}`}
                        style={{ width: `${barWidth}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Worker Status Summary */}
        <div className="space-y-3">
          <div className="flex items-center gap-1.5 text-xs font-medium text-text-secondary">
            <Gauge className="h-3 w-3" />
            Worker Status
          </div>
          <div className="grid grid-cols-2 gap-2">
            <StatBox
              label="Running"
              value={runningWorkers}
              color="text-neon-green"
            />
            <StatBox
              label="Total"
              value={totalWorkers}
              color="text-text-primary"
            />
            <StatBox
              label="Queue Depth"
              value={counters.queueDepth}
              color="text-neon-orange"
            />
            <StatBox
              label="Workers Spawned"
              value={counters.workers}
              color="text-neon-blue"
            />
          </div>
        </div>

        {/* DB Stats from Counters */}
        <div className="space-y-3">
          <div className="flex items-center gap-1.5 text-xs font-medium text-text-secondary">
            <Database className="h-3 w-3" />
            Database Stats
          </div>
          <div className="grid grid-cols-2 gap-2">
            <StatBox
              label="Assets"
              value={counters.assets}
              color="text-neon-blue"
            />
            <StatBox
              label="Vulns"
              value={counters.vulns}
              color="text-danger"
            />
          </div>
          <div className="mt-2 rounded bg-bg-tertiary px-2.5 py-2">
            <div className="flex items-center gap-1.5">
              <span className="relative flex h-1.5 w-1.5">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-neon-green opacity-75" />
                <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-neon-green" />
              </span>
              <span className="text-[10px] text-text-muted">
                Rate limiter: nominal
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function StatBox({
  label,
  value,
  color,
}: {
  label: string;
  value: number;
  color: string;
}) {
  return (
    <div className="rounded bg-bg-tertiary px-2.5 py-2">
      <div className="text-[9px] uppercase tracking-wide text-text-muted">
        {label}
      </div>
      <div className={`mt-0.5 font-mono text-lg font-bold ${color}`}>
        {value}
      </div>
    </div>
  );
}
