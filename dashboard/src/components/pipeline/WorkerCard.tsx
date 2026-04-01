import { useMemo } from "react";
import type { WorkerState } from "@/types/campaign";

interface WorkerCardProps {
  worker: string;
  state: WorkerState;
  totalStages: number;
  dependencies?: string[];
  onClick?: () => void;
}

const STATUS_COLORS: Record<string, string> = {
  pending: "border-gray-600 bg-bg-surface",
  queued: "border-blue-500 bg-blue-500/10",
  running: "border-amber-500 bg-amber-500/10",
  complete: "border-green-500 bg-green-500/10",
  failed: "border-red-500 bg-red-500/10",
  skipped: "border-gray-500 bg-gray-500/10 border-dashed opacity-60",
};

const STATUS_TEXT_COLORS: Record<string, string> = {
  pending: "text-gray-400",
  queued: "text-blue-400",
  running: "text-amber-400",
  complete: "text-green-400",
  failed: "text-red-400",
  skipped: "text-gray-400",
};

export default function WorkerCard({ worker, state, totalStages, onClick }: WorkerCardProps) {
  const currentStage = state.current_stage_index ?? 0;
  const progressPercent = totalStages > 0 ? Math.min((currentStage / totalStages) * 100, 100) : 0;

  const statusLabel = useMemo(() => {
    if (state.skipped) return "Skipped";
    return state.status.charAt(0).toUpperCase() + state.status.slice(1);
  }, [state.status, state.skipped]);

  return (
    <button
      onClick={onClick}
      className={`w-48 rounded-lg border-2 p-3 text-left transition-all hover:scale-105 ${STATUS_COLORS[state.status] || STATUS_COLORS.pending} ${state.status === "running" ? "animate-pulse" : ""}`}
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
        <div className="h-1.5 w-full rounded-full bg-bg-void overflow-hidden">
          <div
            className="h-full rounded-full bg-accent-primary transition-all"
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
        <div className="mt-1 text-xs text-red-400 truncate">
          {state.error}
        </div>
      )}

      {state.skip_reason && (
        <div className="mt-1 text-xs text-gray-400 italic">
          {state.skip_reason}
        </div>
      )}
    </button>
  );
}
