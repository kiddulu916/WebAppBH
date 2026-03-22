import { create } from "zustand";
import { persist } from "zustand/middleware";
import type { Target, JobState } from "@/types/schema";
import type { SSEEvent } from "@/types/events";

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
}

const MAX_EVENTS = 500;

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
