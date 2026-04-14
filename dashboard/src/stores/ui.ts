import { create } from "zustand";
import { persist } from "zustand/middleware";

type Theme = "dark" | "light";

interface UIState {
  sidebarExpanded: boolean;
  dockExpanded: boolean;
  commandPaletteOpen: boolean;
  shortcutsOpen: boolean;
  systemPulseOpen: boolean;
  hasSeenTour: boolean;
  theme: Theme;

  setSidebarExpanded: (v: boolean) => void;
  toggleDock: () => void;
  setDockExpanded: (v: boolean) => void;
  setCommandPaletteOpen: (v: boolean) => void;
  setShortcutsOpen: (v: boolean) => void;
  setSystemPulseOpen: (v: boolean) => void;
  setHasSeenTour: (v: boolean) => void;
  toggleTheme: () => void;
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
      theme: "dark" as Theme,

      setSidebarExpanded: (v) => set({ sidebarExpanded: v }),
      toggleDock: () => set((s) => ({ dockExpanded: !s.dockExpanded })),
      setDockExpanded: (v) => set({ dockExpanded: v }),
      setCommandPaletteOpen: (v) => set({ commandPaletteOpen: v }),
      setShortcutsOpen: (v) => set({ shortcutsOpen: v }),
      setSystemPulseOpen: (v) => set({ systemPulseOpen: v }),
      setHasSeenTour: (v) => set({ hasSeenTour: v }),
      toggleTheme: () =>
        set((s) => {
          const next = s.theme === "dark" ? "light" : "dark";
          document.documentElement.classList.toggle("light", next === "light");
          document.documentElement.classList.toggle("dark", next === "dark");
          return { theme: next };
        }),
    }),
    {
      name: "webbh-ui",
      partialize: (s) => ({
        dockExpanded: s.dockExpanded,
        hasSeenTour: s.hasSeenTour,
        theme: s.theme,
      }),
    },
  ),
);
