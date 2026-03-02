import { create } from "zustand";
import { persist } from "zustand/middleware";
import type { Target, JobState } from "@/types/schema";

interface CampaignState {
  /* data */
  activeTarget: Target | null;
  currentPhase: string | null;
  jobs: JobState[];

  /* connectivity */
  connected: boolean;

  /* actions */
  setActiveTarget: (target: Target | null) => void;
  setCurrentPhase: (phase: string | null) => void;
  setJobs: (jobs: JobState[]) => void;
  setConnected: (v: boolean) => void;
}

export const useCampaignStore = create<CampaignState>()(
  persist(
    (set) => ({
      activeTarget: null,
      currentPhase: null,
      jobs: [],
      connected: false,

      setActiveTarget: (target) => set({ activeTarget: target }),
      setCurrentPhase: (phase) => set({ currentPhase: phase }),
      setJobs: (jobs) => set({ jobs }),
      setConnected: (v) => set({ connected: v }),
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
