import { create } from "zustand";
import type { WorkerState, TargetEvent, ResourceStatus } from "@/types/campaign";

interface PipelineState {
  workerStates: Record<string, WorkerState>;
  resourceStatus: ResourceStatus | null;
  updateFromEvent: (event: TargetEvent) => void;
  setWorkerStates: (states: Record<string, WorkerState>) => void;
  setResourceStatus: (status: ResourceStatus) => void;
}

export const usePipelineStore = create<PipelineState>((set) => ({
  workerStates: {},
  resourceStatus: null,

  updateFromEvent: (event) => {
    switch (event.event) {
      case "worker_queued":
        set((state) => ({
          workerStates: {
            ...state.workerStates,
            [event.worker!]: { status: "queued" },
          },
        }));
        break;

      case "worker_started":
        set((state) => ({
          workerStates: {
            ...state.workerStates,
            [event.worker!]: {
              status: "running",
              started_at: event.timestamp,
              current_stage_index: 0,
            },
          },
        }));
        break;

      case "worker_complete":
        set((state) => ({
          workerStates: {
            ...state.workerStates,
            [event.worker!]: {
              ...state.workerStates[event.worker!],
              status: "complete",
              completed_at: event.timestamp,
            },
          },
        }));
        break;

      case "worker_failed":
        set((state) => ({
          workerStates: {
            ...state.workerStates,
            [event.worker!]: {
              ...state.workerStates[event.worker!],
              status: "failed",
              error: event.error,
            },
          },
        }));
        break;

      case "worker_skipped":
        set((state) => ({
          workerStates: {
            ...state.workerStates,
            [event.worker!]: {
              status: "skipped",
              skipped: true,
              skip_reason: event.data?.reason as string,
            },
          },
        }));
        break;

      case "stage_complete":
        set((state) => {
          const worker = state.workerStates[event.worker!] || {};
          return {
            workerStates: {
              ...state.workerStates,
              [event.worker!]: {
                ...worker,
                current_stage_index: (event.stage_index ?? 0) + 1,
                current_section_id: event.section_id,
              },
            },
          };
        });
        break;
    }
  },

  setWorkerStates: (states) => set({ workerStates: states }),
  setResourceStatus: (status) => set({ resourceStatus: status }),
}));
