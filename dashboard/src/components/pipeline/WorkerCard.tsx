import { useMemo } from "react";
import type { PipelineWorkerState } from "@/types/schema";

interface WorkerCardProps {
  worker: string;
  state: PipelineWorkerState;
  totalStages: number;
  dependencies?: string[];
  isInfra?: boolean;
  onClick?: () => void;
}

const STATUS_COLORS: Record<string, string> = {
  pending: "border-border bg-bg-tertiary",
  queued: "border-neon-blue/30 bg-neon-blue-glow",
  running: "border-neon-orange/30 bg-neon-orange-glow",
  complete: "border-neon-green/30 bg-neon-green-glow",
  failed: "border-danger/30 bg-danger/10",
  skipped: "border-border bg-bg-surface border-dashed opacity-60",
};

const STATUS_TEXT_COLORS: Record<string, string> = {
  pending: "text-text-muted",
  queued: "text-neon-blue",
  running: "text-neon-orange",
  complete: "text-neon-green",
  failed: "text-danger",
  skipped: "text-text-muted",
};

export default function WorkerCard({ worker, state, totalStages, isInfra, onClick }: WorkerCardProps) {
  const currentStage = state.current_stage_index ?? 0;
  const progressPercent = totalStages > 0 ? Math.min((currentStage / totalStages) * 100, 100) : 0;

  const statusLabel = useMemo(() => {
    if (state.skipped) return "Skipped";
    return state.status.charAt(0).toUpperCase() + state.status.slice(1);
  }, [state.status, state.skipped]);

  const runningAnimation = isInfra
    ? state.status === "running" ? "animate-pulse-green" : ""
    : state.status === "running" ? "animate-pulse-orange" : "";

  if (isInfra) {
    return (
      <button
        onClick={onClick}
        className={`w-36 rounded-lg border p-2 text-left transition-all hover:scale-105 ${STATUS_COLORS[state.status] || STATUS_COLORS.pending} ${runningAnimation}`}
      >
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold text-text-primary capitalize">
            {worker.replace(/_/g, " ")}
          </span>
          <span className={`text-[10px] font-medium ${STATUS_TEXT_COLORS[state.status] || STATUS_TEXT_COLORS.pending}`}>
            {statusLabel}
          </span>
        </div>
      </button>
    );
  }

  return (
    <button
      onClick={onClick}
      className={`w-48 rounded-lg border-2 p-3 text-left transition-all hover:scale-105 ${STATUS_COLORS[state.status] || STATUS_COLORS.pending} ${runningAnimation}`}
    >
      <div className="flex items-center justify-between mb-2">
        <span className="text-sm font-semibold text-text-primary capitalize">
          {worker.replace(/_/g, " ")}
        </span>
        <span className={`text-xs font-medium ${STATUS_TEXT_COLORS[state.status] || STATUS_TEXT_COLORS.pending}`}>
          {statusLabel}
        </span>
      </div>

      <div className="mb-1">
        <div className="h-1.5 w-full rounded-full bg-bg-tertiary overflow-hidden">
          <div
            className="h-full rounded-full bg-accent transition-all"
            style={{ width: `${progressPercent}%` }}
          />
        </div>
      </div>

      <div className="text-xs text-text-secondary">
        {currentStage}/{totalStages} stages
      </div>

      {state.last_tool_executed && (
        <div className="mt-1 text-xs text-text-secondary truncate">
          Last: {state.last_tool_executed}
        </div>
      )}

      {state.error && (
        <div className="mt-1 text-xs text-danger truncate">
          {state.error}
        </div>
      )}

      {state.skip_reason && (
        <div className="mt-1 text-xs text-text-muted italic">
          {state.skip_reason}
        </div>
      )}
    </button>
  );
}
