"use client";

import { useEffect, useRef, useState } from "react";
import { useCampaignStore } from "@/stores/campaign";

export default function FooterBar() {
  const { counters, jobs, connected } = useCampaignStore();
  const prevCounters = useRef(counters);
  const [changed, setChanged] = useState({ assets: false, vulns: false, workers: false });

  const runningCount = jobs.filter((j) => j.status === "RUNNING").length;
  const queuedCount = jobs.filter((j) => j.status === "QUEUED").length;

  // Track which counters just changed for the bump animation
  useEffect(() => {
    const prev = prevCounters.current;
    setChanged({
      assets: counters.assets !== prev.assets,
      vulns: counters.vulns !== prev.vulns,
      workers: counters.workers !== prev.workers,
    });
    prevCounters.current = counters;
  }, [counters]);

  return (
    <footer className="flex h-7 items-center justify-between border-t border-border bg-bg-secondary px-4 text-[10px] font-mono">
      <div className="flex items-center gap-4">
        <Stat
          label="Workers"
          value={runningCount}
          suffix={queuedCount > 0 ? `+${queuedCount} queued` : undefined}
          color="text-neon-green"
          bump={changed.workers}
        />
        <span className="contents" data-testid="footer-asset-count">
          <Stat
            label="Assets"
            value={counters.assets}
            color="text-neon-blue"
            bump={changed.assets}
          />
        </span>
        <span className="contents" data-testid="footer-vuln-count">
          <Stat
            label="Vulns"
            value={counters.vulns}
            color="text-neon-orange"
            bump={changed.vulns}
          />
        </span>
      </div>

      <div className="flex items-center gap-3 text-text-muted">
        <span>
          SSE: {connected ? (
            <span className="text-neon-green">connected</span>
          ) : (
            <span className="text-danger">disconnected</span>
          )}
        </span>
      </div>
    </footer>
  );
}

function Stat({
  label,
  value,
  suffix,
  color,
  bump,
}: {
  label: string;
  value: number;
  suffix?: string;
  color: string;
  bump: boolean;
}) {
  return (
    <div className="flex items-center gap-1.5 text-text-muted">
      <span>{label}:</span>
      <span className={`${color} ${bump ? "animate-counter-bump" : ""}`} key={value}>
        {value.toLocaleString()}
      </span>
      {suffix && <span className="text-text-muted">{suffix}</span>}
    </div>
  );
}
