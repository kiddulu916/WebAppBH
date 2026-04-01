"use client";

import type { WorkerState } from "@/types/campaign";

interface WorkerDetailDrawerProps {
  worker: string;
  state: WorkerState;
  stages: { id: string; name: string; sectionId: string }[];
  findingCount: number;
  onClose: () => void;
}

export default function WorkerDetailDrawer({ worker, state, stages, findingCount, onClose }: WorkerDetailDrawerProps) {
  const currentStageIndex = state.current_stage_index ?? 0;

  return (
    <div className="fixed inset-0 z-50 flex justify-end" onClick={onClose}>
      <div className="absolute inset-0 bg-black/50" />
      <div
        className="relative w-96 h-full bg-bg-surface border-l border-border overflow-y-auto"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="p-4 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-bold text-text-primary capitalize">
              {worker.replace(/_/g, " ")}
            </h2>
            <button
              onClick={onClose}
              className="text-text-secondary hover:text-text-primary text-xl"
            >
              ×
            </button>
          </div>

          <div className="space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-text-secondary">Status</span>
              <span className="text-text-primary capitalize">{state.status}</span>
            </div>
            {state.started_at && (
              <div className="flex justify-between">
                <span className="text-text-secondary">Started</span>
                <span className="text-text-primary">{new Date(state.started_at).toLocaleString()}</span>
              </div>
            )}
            {state.completed_at && state.started_at && (
              <div className="flex justify-between">
                <span className="text-text-secondary">Duration</span>
                <span className="text-text-primary">
                  {Math.round((new Date(state.completed_at).getTime() - new Date(state.started_at).getTime()) / 1000)}s
                </span>
              </div>
            )}
            <div className="flex justify-between">
              <span className="text-text-secondary">Findings</span>
              <span className="text-text-primary">{findingCount}</span>
            </div>
          </div>

          <div className="space-y-2">
            <h3 className="text-sm font-semibold text-text-primary">Stages</h3>
            {stages.map((stage, idx) => {
              const isCompleted = idx < currentStageIndex;
              const isCurrent = idx === currentStageIndex && state.status === "running";
              const isPending = idx > currentStageIndex;

              return (
                <div
                  key={stage.id}
                  className={`flex items-center gap-2 p-2 rounded text-sm ${
                    isCompleted
                      ? "bg-green-500/10 text-green-400"
                      : isCurrent
                        ? "bg-amber-500/10 text-amber-400"
                        : isPending
                          ? "bg-bg-void text-gray-500"
                          : "text-text-secondary"
                  }`}
                >
                  <span className="w-4">
                    {isCompleted ? "✓" : isCurrent ? "⟳" : "○"}
                  </span>
                  <div className="flex-1">
                    <div className="font-medium">{stage.name}</div>
                    <div className="text-xs opacity-70">{stage.sectionId}</div>
                  </div>
                </div>
              );
            })}
          </div>

          {state.error && (
            <div className="p-3 rounded bg-red-500/10 border border-red-500/30">
              <div className="text-sm font-medium text-red-400">Error</div>
              <div className="text-xs text-red-300 mt-1">{state.error}</div>
            </div>
          )}

          {state.skip_reason && (
            <div className="p-3 rounded bg-gray-500/10 border border-gray-500/30">
              <div className="text-sm font-medium text-gray-400">Skipped</div>
              <div className="text-xs text-gray-300 mt-1">{state.skip_reason}</div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
