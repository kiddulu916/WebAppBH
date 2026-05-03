"use client";

import { useState } from "react";
import type { ResourceStatus } from "@/types/schema";

interface ResourcePanelProps {
  status: ResourceStatus | null;
  onClose: () => void;
}

const TIER_COLORS: Record<string, string> = {
  green: "text-neon-green",
  yellow: "text-warning",
  red: "text-danger",
  critical: "text-danger font-bold",
};

function ProgressBar({ value, max, label }: { value: number; max: number; label: string }) {
  const percent = Math.min((value / max) * 100, 100);
  const color = percent > 90 ? "bg-danger" : percent > 70 ? "bg-warning" : "bg-neon-green";

  return (
    <div className="space-y-1">
      <div className="flex justify-between text-xs">
        <span className="text-text-secondary">{label}</span>
        <span className="text-text-primary">
          {value.toFixed(0)}% / {max}%
        </span>
      </div>
      <div className="h-2 rounded-full bg-bg-void overflow-hidden">
        <div className={`h-full rounded-full ${color} transition-all`} style={{ width: `${percent}%` }} />
      </div>
    </div>
  );
}

export default function ResourcePanel({ status, onClose }: ResourcePanelProps) {
  const [showOverrides, setShowOverrides] = useState(false);

  if (!status) {
    return (
      <div className="fixed inset-0 z-50 flex justify-end" onClick={onClose}>
        <div className="absolute inset-0 bg-black/50" />
        <div className="relative w-80 h-full bg-bg-surface border-l border-border p-4">
          <div className="text-text-secondary">No resource status available</div>
        </div>
      </div>
    );
  }

  return (
    <div className="fixed inset-0 z-50 flex justify-end" onClick={onClose}>
      <div className="absolute inset-0 bg-black/50" />
      <div
        className="relative w-80 h-full bg-bg-surface border-l border-border overflow-y-auto"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="p-4 space-y-6">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-bold text-text-primary">Resource Guard</h2>
            <button onClick={onClose} className="text-text-secondary hover:text-text-primary text-xl">
              ×
            </button>
          </div>

          {/* Current tier */}
          <div className="rounded-lg border border-border p-4 bg-bg-void">
            <div className="text-sm text-text-secondary mb-1">Current Tier</div>
            <div className={`text-2xl font-bold capitalize ${TIER_COLORS[status.tier]}`}>
              {status.tier}
            </div>
          </div>

          {/* Metrics */}
          <div className="space-y-4">
            <ProgressBar
              value={status.cpu_percent}
              max={status.thresholds.red.cpu}
              label="CPU Usage"
            />
            <ProgressBar
              value={status.memory_percent}
              max={status.thresholds.red.memory}
              label="Memory Usage"
            />
          </div>

          {/* Workers */}
          <div className="rounded-lg border border-border p-4 bg-bg-void">
            <div className="text-sm text-text-secondary mb-1">Active Workers</div>
            <div className="text-2xl font-bold text-text-primary">
              {status.active_workers}
            </div>
            <div className="text-xs text-text-secondary mt-1">
              Threshold: {status.thresholds.yellow.workers} (yellow) / {status.thresholds.red.workers} (red)
            </div>
          </div>

          {/* Thresholds */}
          <div className="rounded-lg border border-border p-4 bg-bg-void">
            <div className="text-sm font-medium text-text-primary mb-2">Thresholds</div>
            <div className="space-y-2 text-xs">
              <div className="flex justify-between">
                <span className="text-neon-green">Green</span>
                <span className="text-text-secondary">
                  CPU: {status.thresholds.green.cpu}% | Mem: {status.thresholds.green.memory}% | Workers: {status.thresholds.green.workers}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-warning">Yellow</span>
                <span className="text-text-secondary">
                  CPU: {status.thresholds.yellow.cpu}% | Mem: {status.thresholds.yellow.memory}% | Workers: {status.thresholds.yellow.workers}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-danger">Red</span>
                <span className="text-text-secondary">
                  CPU: {status.thresholds.red.cpu}% | Mem: {status.thresholds.red.memory}% | Workers: {status.thresholds.red.workers}
                </span>
              </div>
            </div>
          </div>

          {/* Admin overrides */}
          <button
            onClick={() => setShowOverrides(!showOverrides)}
            className="w-full text-sm text-accent hover:underline"
          >
            {showOverrides ? "Hide" : "Show"} Admin Overrides
          </button>

          {showOverrides && (
            <div className="space-y-3">
              <div>
                <label className="block text-xs text-text-secondary mb-1">Override Tier</label>
                <select className="w-full rounded-md border border-border bg-bg-surface px-3 py-2 text-sm text-text-primary">
                  <option value="green">Green</option>
                  <option value="yellow">Yellow</option>
                  <option value="red">Red</option>
                  <option value="critical">Critical</option>
                </select>
              </div>
              <button className="w-full rounded-md bg-accent px-4 py-2 text-sm font-medium text-white hover:bg-accent-hover">
                Apply Override
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
