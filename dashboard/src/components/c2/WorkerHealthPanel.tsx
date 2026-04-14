"use client";

import { useEffect, useState, useCallback } from "react";
import {
  Activity,
  Cpu,
  HardDrive,
  RefreshCw,
  Loader2,
  AlertTriangle,
  CheckCircle2,
} from "lucide-react";
import { api } from "@/lib/api";
import type { WorkerHealthEntry } from "@/lib/api";

export default function WorkerHealthPanel() {
  const [host, setHost] = useState<{
    cpu_percent: number;
    memory_percent: number;
    is_healthy: boolean;
  } | null>(null);
  const [workers, setWorkers] = useState<WorkerHealthEntry[]>([]);
  const [loading, setLoading] = useState(true);

  const fetch = useCallback(async () => {
    try {
      const res = await api.getWorkerHealth();
      setHost(res.host);
      setWorkers(res.workers);
    } catch {
      // toast shown by api.request()
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetch();
    const interval = setInterval(fetch, 15_000);
    return () => clearInterval(interval);
  }, [fetch]);

  if (loading) {
    return (
      <div className="flex h-48 items-center justify-center rounded-lg border border-border bg-bg-secondary">
        <Loader2 className="h-5 w-5 animate-spin text-accent" />
      </div>
    );
  }

  const running = workers.filter((w) => w.status === "running");
  const stopped = workers.filter((w) => w.status !== "running");

  return (
    <div className="space-y-4 rounded-lg border border-border bg-bg-secondary p-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Activity className="h-4 w-4 text-neon-blue" />
          <span className="section-label">WORKER HEALTH</span>
        </div>
        <button
          onClick={() => { setLoading(true); fetch(); }}
          className="flex items-center gap-1 rounded px-2 py-1 text-[10px] text-text-muted hover:bg-bg-tertiary hover:text-text-primary"
        >
          <RefreshCw className="h-3 w-3" />
          Refresh
        </button>
      </div>

      {/* Host metrics */}
      {host && (
        <div className="flex items-center gap-4 rounded-md bg-bg-tertiary px-3 py-2">
          <div className="flex items-center gap-1.5">
            {host.is_healthy ? (
              <CheckCircle2 className="h-3.5 w-3.5 text-neon-green" />
            ) : (
              <AlertTriangle className="h-3.5 w-3.5 text-danger" />
            )}
            <span className="text-[10px] font-medium text-text-secondary">HOST</span>
          </div>
          <HostGauge icon={Cpu} label="CPU" value={host.cpu_percent} />
          <HostGauge icon={HardDrive} label="MEM" value={host.memory_percent} />
        </div>
      )}

      {/* Running workers */}
      {running.length > 0 && (
        <div className="space-y-2">
          <span className="text-[10px] font-medium uppercase text-text-muted">
            Running ({running.length})
          </span>
          <div className="grid grid-cols-3 gap-2">
            {running.map((w) => (
              <WorkerHealthCard key={w.name} worker={w} />
            ))}
          </div>
        </div>
      )}

      {/* Stopped workers */}
      {stopped.length > 0 && (
        <div className="space-y-2">
          <span className="text-[10px] font-medium uppercase text-text-muted">
            Inactive ({stopped.length})
          </span>
          <div className="grid grid-cols-4 gap-2">
            {stopped.map((w) => (
              <div
                key={w.name}
                className="flex items-center gap-2 rounded bg-bg-tertiary px-2 py-1.5"
              >
                <span className="h-1.5 w-1.5 rounded-full bg-text-muted" />
                <span className="truncate font-mono text-[10px] text-text-muted">
                  {w.name.replace("webbh-", "")}
                </span>
                {w.restart_count > 0 && (
                  <span className="ml-auto font-mono text-[9px] text-warning">
                    {w.restart_count}x
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function HostGauge({
  icon: Icon,
  label,
  value,
}: {
  icon: React.ElementType;
  label: string;
  value: number;
}) {
  const color =
    value > 85 ? "text-danger" : value > 70 ? "text-warning" : "text-neon-green";
  return (
    <div className="flex items-center gap-1.5">
      <Icon className="h-3 w-3 text-text-muted" />
      <span className="text-[10px] text-text-muted">{label}</span>
      <span className={`font-mono text-xs font-bold ${color}`}>
        {value.toFixed(1)}%
      </span>
    </div>
  );
}

function WorkerHealthCard({ worker }: { worker: WorkerHealthEntry }) {
  const cpuColor =
    (worker.cpu_percent ?? 0) > 80
      ? "text-danger"
      : (worker.cpu_percent ?? 0) > 50
        ? "text-warning"
        : "text-neon-green";

  const memPct =
    worker.memory_mb && worker.memory_limit_mb && worker.memory_limit_mb > 0
      ? (worker.memory_mb / worker.memory_limit_mb) * 100
      : 0;

  return (
    <div className="rounded-lg border border-neon-green/10 bg-bg-tertiary p-2.5">
      <div className="flex items-center justify-between">
        <span className="truncate font-mono text-[10px] text-text-primary">
          {worker.name.replace("webbh-", "")}
        </span>
        <span className="h-1.5 w-1.5 rounded-full bg-neon-green" />
      </div>
      <div className="mt-2 space-y-1">
        <div className="flex items-center justify-between text-[10px]">
          <span className="text-text-muted">CPU</span>
          <span className={`font-mono ${cpuColor}`}>
            {worker.cpu_percent != null ? `${worker.cpu_percent}%` : "—"}
          </span>
        </div>
        <div className="flex items-center justify-between text-[10px]">
          <span className="text-text-muted">MEM</span>
          <span className="font-mono text-text-secondary">
            {worker.memory_mb != null ? `${worker.memory_mb}MB` : "—"}
          </span>
        </div>
        {memPct > 0 && (
          <div className="h-1 rounded-full bg-bg-surface">
            <div
              className={`h-full rounded-full transition-all ${
                memPct > 80 ? "bg-danger" : memPct > 60 ? "bg-warning" : "bg-neon-green"
              }`}
              style={{ width: `${Math.min(memPct, 100)}%` }}
            />
          </div>
        )}
        {worker.restart_count > 0 && (
          <div className="flex items-center gap-1 text-[9px] text-warning">
            <AlertTriangle className="h-2.5 w-2.5" />
            {worker.restart_count} restarts
          </div>
        )}
      </div>
    </div>
  );
}
