import { create } from "zustand";
import { persist } from "zustand/middleware";
import type { Target, JobState, Campaign, PipelineWorkerState, ResourceStatus } from "@/types/schema";
import type { SSEEvent } from "@/types/events";

/** Event shape used by the SSE pipeline handler (worker lifecycle events). */
interface PipelineEvent {
  event: string;
  worker?: string;
  timestamp?: string;
  error?: string;
  stage_index?: number;
  section_id?: string;
  data?: Record<string, unknown>;
}

interface CampaignState {
  /* data */
  activeTarget: Target | null;
  currentPhase: string | null;
  jobs: JobState[];
  unreadAlerts: number;

  /* SSE events (global, consumed by BottomDock + any component) */
  events: SSEEvent[];

  /* live counters (incremented by SSE, displayed in FooterBar) */
  counters: {
    assets: number;
    vulns: number;
    workers: number;
    queueDepth: number;
  };

  /* connectivity */
  connected: boolean;

  /* pipeline (merged from pipelineStore) */
  workerStates: Record<string, PipelineWorkerState>;
  resourceStatus: ResourceStatus | null;

  /* campaign (merged from campaignStore) */
  activeCampaign: Campaign | null;

  /* actions */
  setActiveTarget: (target: Target | null) => void;
  setCurrentPhase: (phase: string | null) => void;
  setJobs: (jobs: JobState[]) => void;
  setConnected: (v: boolean) => void;
  setUnreadAlerts: (count: number) => void;
  incrementUnreadAlerts: () => void;
  decrementUnreadAlerts: () => void;

  /* event actions */
  pushEvent: (evt: SSEEvent) => void;
  clearEvents: () => void;

  /* counter actions */
  setCounters: (c: Partial<CampaignState["counters"]>) => void;
  bumpCounter: (key: keyof CampaignState["counters"], delta?: number) => void;

  /* pipeline actions */
  setWorkerStates: (states: Record<string, PipelineWorkerState>) => void;
  updateWorkerState: (worker: string, update: Partial<PipelineWorkerState>) => void;
  updateFromEvent: (event: PipelineEvent) => void;
  setResourceStatus: (status: ResourceStatus) => void;

  /* campaign actions */
  setActiveCampaign: (campaign: Campaign | null) => void;
}

const MAX_EVENTS = 500;

/* eslint-disable @typescript-eslint/no-explicit-any */
export const useCampaignStore = create<CampaignState>()(
  persist(
    (set) => ({
      activeTarget: null,
      currentPhase: null,
      jobs: [],
      unreadAlerts: 0,
      events: [],
      counters: { assets: 0, vulns: 0, workers: 0, queueDepth: 0 },
      connected: false,
      workerStates: {},
      resourceStatus: null,
      activeCampaign: null,

      setActiveTarget: (target) =>
        set({ activeTarget: target, events: [], counters: { assets: 0, vulns: 0, workers: 0, queueDepth: 0 } }),
      setCurrentPhase: (phase) => set({ currentPhase: phase }),
      setJobs: (jobs) => set({ jobs }),
      setConnected: (v) => set({ connected: v }),
      setUnreadAlerts: (count) => set({ unreadAlerts: count }),
      incrementUnreadAlerts: () =>
        set((s) => ({ unreadAlerts: s.unreadAlerts + 1 })),
      decrementUnreadAlerts: () =>
        set((s) => ({ unreadAlerts: Math.max(0, s.unreadAlerts - 1) })),

      pushEvent: (evt) =>
        set((s) => ({ events: [...s.events.slice(-(MAX_EVENTS - 1)), evt] })),
      clearEvents: () => set({ events: [] }),

      setCounters: (c) =>
        set((s) => ({ counters: { ...s.counters, ...c } })),
      bumpCounter: (key, delta = 1) =>
        set((s) => ({ counters: { ...s.counters, [key]: s.counters[key] + delta } })),

      setWorkerStates: (states) => set({ workerStates: states }),
      updateWorkerState: (worker, update) =>
        set((s) => ({
          workerStates: {
            ...s.workerStates,
            [worker]: { ...s.workerStates[worker], ...update },
          },
        })),
      updateFromEvent: (event) => {
        switch (event.event) {
          case "worker_queued":
            set((s) => ({
              workerStates: {
                ...s.workerStates,
                [event.worker!]: { status: "queued" },
              },
            }));
            break;
          case "worker_started":
            set((s) => ({
              workerStates: {
                ...s.workerStates,
                [event.worker!]: {
                  status: "running",
                  started_at: event.timestamp,
                  current_stage_index: 0,
                },
              },
            }));
            break;
          case "worker_complete":
            set((s) => ({
              workerStates: {
                ...s.workerStates,
                [event.worker!]: {
                  ...s.workerStates[event.worker!],
                  status: "complete",
                  completed_at: event.timestamp,
                },
              },
            }));
            break;
          case "worker_failed":
            set((s) => ({
              workerStates: {
                ...s.workerStates,
                [event.worker!]: {
                  ...s.workerStates[event.worker!],
                  status: "failed",
                  error: event.error,
                },
              },
            }));
            break;
          case "worker_skipped":
            set((s) => ({
              workerStates: {
                ...s.workerStates,
                [event.worker!]: {
                  status: "skipped",
                  skipped: true,
                  skip_reason: event.data?.reason as string,
                },
              },
            }));
            break;
          case "stage_complete":
            set((s) => {
              const worker = s.workerStates[event.worker!] || {};
              return {
                workerStates: {
                  ...s.workerStates,
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
      setResourceStatus: (status) => set({ resourceStatus: status }),
      setActiveCampaign: (campaign) => set({ activeCampaign: campaign }),
    }),
    {
      name: "webbh-campaign",
      partialize: (s) => ({
        activeTarget: s.activeTarget,
        currentPhase: s.currentPhase,
      }),
    },
  ),
);

// Expose store on window for e2e testing (Playwright page.evaluate access)
if (typeof window !== "undefined") {
  (window as any).__campaignStore = useCampaignStore;
}
