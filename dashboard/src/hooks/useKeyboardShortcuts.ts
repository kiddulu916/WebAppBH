"use client";

import { useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import { useUIStore } from "@/stores/ui";

/**
 * Global keyboard shortcuts.
 * Vim-style two-key combos: g+d → Dashboard, g+c → C2, etc.
 * Single keys: ? → shortcuts help, l → toggle dock, p → toggle pulse
 */
export function useKeyboardShortcuts() {
  const router = useRouter();
  const pendingPrefix = useRef<string | null>(null);
  const timeout = useRef<ReturnType<typeof setTimeout>>(undefined);

  useEffect(() => {
    function handle(e: KeyboardEvent) {
      // Ignore if user is typing in an input/textarea
      const tag = (e.target as HTMLElement)?.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;
      // Ignore if modifier keys are held (except for cmd+k which CommandPalette handles)
      if (e.metaKey || e.ctrlKey || e.altKey) return;

      const key = e.key.toLowerCase();

      // Handle "g" prefix combos
      if (pendingPrefix.current === "g") {
        pendingPrefix.current = null;
        clearTimeout(timeout.current);
        e.preventDefault();

        const routes: Record<string, string> = {
          d: "/",
          n: "/campaign",
          c: "/campaign/c2",
          f: "/campaign/flow",
          g: "/campaign/graph",
          a: "/campaign/assets",
          v: "/campaign/vulns",
        };

        if (routes[key]) {
          router.push(routes[key]);
        }
        return;
      }

      // Start "g" prefix
      if (key === "g") {
        pendingPrefix.current = "g";
        timeout.current = setTimeout(() => {
          pendingPrefix.current = null;
        }, 500);
        return;
      }

      // Single-key shortcuts
      if (key === "?") {
        e.preventDefault();
        useUIStore.getState().setShortcutsOpen(
          !useUIStore.getState().shortcutsOpen
        );
      } else if (key === "l") {
        e.preventDefault();
        useUIStore.getState().toggleDock();
      } else if (key === "p") {
        e.preventDefault();
        useUIStore.getState().setSystemPulseOpen(
          !useUIStore.getState().systemPulseOpen
        );
      } else if (key === "t") {
        e.preventDefault();
        useUIStore.getState().toggleTheme();
      }
    }

    document.addEventListener("keydown", handle);
    return () => document.removeEventListener("keydown", handle);
  }, [router]);
}
