// dashboard/src/components/assets/PortsList.tsx
"use client";

import type { Location } from "@/types/schema";

const STATE_BADGE: Record<string, string> = {
  open: "bg-neon-green-glow text-neon-green border-neon-green/20",
  closed: "bg-bg-surface text-text-muted border-border",
  filtered: "bg-sev-medium/10 text-sev-medium border-sev-medium/20",
};

export default function PortsList({
  locations,
  selectedId,
  onSelect,
}: {
  locations: Location[];
  selectedId: number | null;
  onSelect: (loc: Location) => void;
}) {
  if (locations.length === 0) {
    return (
      <p className="py-4 text-center text-xs text-text-muted">No ports found.</p>
    );
  }

  return (
    <div className="space-y-1">
      {locations.map((loc) => (
        <button
          key={loc.id}
          data-testid={`port-row-${loc.id}`}
          onClick={() => onSelect(loc)}
          className={`w-full rounded px-3 py-2 text-left text-xs transition-colors ${
            selectedId === loc.id
              ? "bg-neon-orange/10 text-neon-orange"
              : "hover:bg-bg-tertiary text-text-primary"
          }`}
        >
          <div className="flex items-center justify-between gap-2">
            <span className="font-mono font-medium">:{loc.port}</span>
            <span
              className={`rounded border px-1.5 py-0 text-[10px] font-medium ${
                STATE_BADGE[loc.state ?? ""] ?? STATE_BADGE.closed
              }`}
            >
              {loc.state ?? "—"}
            </span>
          </div>
          {loc.service && (
            <div className="mt-0.5 font-mono text-[10px] text-text-muted">
              {loc.service}
            </div>
          )}
          {loc.protocol && (
            <div className="font-mono text-[10px] text-text-muted">
              {loc.protocol}
            </div>
          )}
        </button>
      ))}
    </div>
  );
}
