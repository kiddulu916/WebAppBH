"use client";

import { useUIStore } from "@/stores/ui";

const SHORTCUTS = [
  { keys: "g d", desc: "Go to Dashboard" },
  { keys: "g n", desc: "New Campaign" },
  { keys: "g c", desc: "C2 Console" },
  { keys: "g f", desc: "Phase Flow" },
  { keys: "g g", desc: "Attack Graph" },
  { keys: "g a", desc: "Assets" },
  { keys: "g v", desc: "Vulnerabilities" },
  { keys: "\u2318 K", desc: "Command Palette" },
  { keys: "l", desc: "Toggle Live Feed" },
  { keys: "p", desc: "Toggle System Pulse" },
  { keys: "?", desc: "This help" },
  { keys: "Esc", desc: "Close overlay" },
];

export default function ShortcutsOverlay() {
  const { shortcutsOpen, setShortcutsOpen } = useUIStore();

  if (!shortcutsOpen) return null;

  return (
    <>
      <div
        className="fixed inset-0 z-50 bg-black/50"
        onClick={() => setShortcutsOpen(false)}
      />
      <div className="fixed left-1/2 top-1/2 z-50 w-full max-w-xs -translate-x-1/2 -translate-y-1/2 animate-fade-in">
        <div className="rounded-lg border border-border-accent bg-bg-secondary p-4 shadow-2xl">
          <h2 className="section-label mb-3">Keyboard Shortcuts</h2>
          <div className="space-y-1.5">
            {SHORTCUTS.map(({ keys, desc }) => (
              <div key={keys} className="flex items-center justify-between text-xs">
                <span className="text-text-secondary">{desc}</span>
                <div className="flex gap-1">
                  {keys.split(" ").map((k) => (
                    <kbd
                      key={k}
                      className="min-w-[20px] rounded border border-border bg-bg-tertiary px-1.5 py-0.5 text-center text-[10px] font-mono text-text-muted"
                    >
                      {k}
                    </kbd>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </>
  );
}
