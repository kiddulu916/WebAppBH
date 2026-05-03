import { useMemo } from "react";
import WorkerCard from "./WorkerCard";
import type { PipelineWorkerState } from "@/types/schema";
import { WORKER_STAGE_COUNTS, WORKER_DEPENDENCIES, INFRA_WORKER_NAMES } from "@/types/schema";

interface PipelineGridProps {
  workerStates: Record<string, PipelineWorkerState>;
  onWorkerClick?: (worker: string) => void;
}

export default function PipelineGrid({ workerStates, onWorkerClick }: PipelineGridProps) {
  const infraWorkers = useMemo(() => [...INFRA_WORKER_NAMES], []);

  const rows = useMemo(() => [
    ["info_gathering", "config_mgmt", "identity_mgmt", "authentication"],
    ["authorization", "session_mgmt", "input_validation"],
    ["error_handling", "cryptography", "business_logic", "client_side", "mobile_worker"],
    ["reasoning_worker", "chain_worker"],
    ["reporting"],
  ], []);

  return (
    <div className="space-y-4">
      {/* Infrastructure shelf */}
      <div className="rounded-lg border border-dashed border-border-accent bg-bg-tertiary/50 p-3">
        <div className="section-label mb-2">INFRASTRUCTURE</div>
        <div className="flex gap-3 justify-center">
          {infraWorkers.map((worker) => {
            const state = workerStates[worker] || { status: "pending" };
            return (
              <WorkerCard
                key={worker}
                worker={worker}
                state={state}
                totalStages={0}
                isInfra
                onClick={() => onWorkerClick?.(worker)}
              />
            );
          })}
        </div>
      </div>

      {/* Pipeline rows */}
      {rows.map((row, rowIdx) => (
        <div key={rowIdx} className="flex gap-4 items-center justify-center">
          {row.map((worker) => {
            const state = workerStates[worker] || { status: "pending" };
            const totalStages = WORKER_STAGE_COUNTS[worker] || 0;
            return (
              <WorkerCard
                key={worker}
                worker={worker}
                state={state}
                totalStages={totalStages}
                dependencies={WORKER_DEPENDENCIES[worker] || []}
                onClick={() => onWorkerClick?.(worker)}
              />
            );
          })}
        </div>
      ))}
    </div>
  );
}
