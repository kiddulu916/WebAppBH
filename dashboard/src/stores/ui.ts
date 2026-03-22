import { create } from "zustand";
import { persist } from "zustand/middleware";

interface UIState {
  sidebarExpanded: boolean;
  dockExpanded: boolean;
  commandPaletteOpen: boolean;
  shortcutsOpen: boolean;
  systemPulseOpen: boolean;
  hasSeenTour: boolean;

  setSidebarExpanded: (v: boolean) => void;
  toggleDock: () => void;
  setDockExpanded: (v: boolean) => void;
  setCommandPaletteOpen: (v: boolean) => void;
  setShortcutsOpen: (v: boolean) => void;
  setSystemPulseOpen: (v: boolean) => void;
  setHasSeenTour: (v: boolean) => void;
}

export const useUIStore = create<UIState>()(
  persist(
    (set) => ({
      sidebarExpanded: false,
      dockExpanded: false,
      commandPaletteOpen: false,
      shortcutsOpen: false,
      systemPulseOpen: false,
      hasSeenTour: false,

      setSidebarExpanded: (v) => set({ sidebarExpanded: v }),
      toggleDock: () => set((s) => ({ dockExpanded: !s.dockExpanded })),
      setDockExpanded: (v) => set({ dockExpanded: v }),
      setCommandPaletteOpen: (v) => set({ commandPaletteOpen: v }),
      setShortcutsOpen: (v) => set({ shortcutsOpen: v }),
      setSystemPulseOpen: (v) => set({ systemPulseOpen: v }),
      setHasSeenTour: (v) => set({ hasSeenTour: v }),
    }),
    {
      name: "webbh-ui",
      partialize: (s) => ({
        dockExpanded: s.dockExpanded,
        hasSeenTour: s.hasSeenTour,
      }),
    },
  ),
);
