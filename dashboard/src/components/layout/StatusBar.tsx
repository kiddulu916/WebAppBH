"use client";

import { Activity, Wifi, WifiOff } from "lucide-react";
import { useCampaignStore } from "@/stores/campaign";

export default function StatusBar() {
  const { connected, activeTarget, currentPhase } = useCampaignStore();

  return (
    <header className="sticky top-0 z-20 flex h-14 items-center justify-between border-b border-border bg-bg-secondary px-6">
      {/* Left — active campaign info */}
      <div className="flex items-center gap-4">
        {activeTarget ? (
          <>
            <span className="text-sm text-text-secondary">Campaign:</span>
            <span className="text-sm font-medium text-text-primary">
              {activeTarget.base_domain}
            </span>
            {currentPhase && (
              <span className="rounded bg-bg-surface px-2 py-0.5 text-xs text-accent">
                {currentPhase}
              </span>
            )}
          </>
        ) : (
          <span className="text-sm text-text-muted">No active campaign</span>
        )}
      </div>

      {/* Right — connection indicator */}
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-1.5">
          {connected ? (
            <>
              <Wifi className="h-3.5 w-3.5 text-success" />
              <span className="text-xs text-success">Connected</span>
            </>
          ) : (
            <>
              <WifiOff className="h-3.5 w-3.5 text-danger" />
              <span className="text-xs text-danger">Disconnected</span>
            </>
          )}
        </div>
        <Activity className="h-4 w-4 animate-pulse text-accent" />
      </div>
    </header>
  );
}
