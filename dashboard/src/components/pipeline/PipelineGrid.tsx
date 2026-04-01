import { useMemo } from "react";
import WorkerCard from "./WorkerCard";
import type { WorkerState } from "@/types/campaign";
import { WORKER_STAGE_COUNTS } from "@/types/campaign";

interface PipelineGridProps {
  workerStates: Record<string, WorkerState>;
  onWorkerClick?: (worker: string) => void;
}

const WORKER_DEPENDENCIES: Record<string, string[]> = {
  info_gathering: [],
  config_mgmt: ["info_gathering"],
  identity_mgmt: ["config_mgmt"],
  authentication: ["identity_mgmt"],
  authorization: ["authentication"],
  session_mgmt: ["authentication"],
  input_validation: ["authentication"],
  error_handling: ["authorization", "session_mgmt", "input_validation"],
  cryptography: ["authorization", "session_mgmt", "input_validation"],
  business_logic: ["authorization", "session_mgmt", "input_validation"],
  client_side: ["authorization", "session_mgmt", "input_validation"],
  chain_worker: ["error_handling", "cryptography", "business_logic", "client_side"],
  reporting: ["chain_worker"],
};

export default function PipelineGrid({ workerStates, onWorkerClick }: PipelineGridProps) {
  const rows = useMemo(() => {
    const row1 = ["info_gathering", "config_mgmt", "identity_mgmt", "authentication"];
    const row2 = ["authorization", "session_mgmt", "input_validation"];
    const row3 = ["error_handling", "cryptography", "business_logic", "client_side"];
    const row4 = ["chain_worker"];
    const row5 = ["reporting"];
    return [row1, row2, row3, row4, row5];
  }, []);

  return (
    <div className="space-y-4">
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
