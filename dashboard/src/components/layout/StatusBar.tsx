"use client";

import { useEffect, useState, useRef } from "react";
import { useRouter } from "next/navigation";
import { Activity, ChevronDown, Wifi, WifiOff } from "lucide-react";
import { api } from "@/lib/api";
import { useCampaignStore } from "@/stores/campaign";
import AlertDropdown from "@/components/layout/AlertDropdown";
import type { Target } from "@/types/schema";

export default function StatusBar() {
  const router = useRouter();
  const { connected, activeTarget, currentPhase, setActiveTarget } =
    useCampaignStore();
  const [open, setOpen] = useState(false);
  const [targets, setTargets] = useState<Target[]>([]);
  const ref = useRef<HTMLDivElement>(null);

  // Close on outside click
  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, []);

  // Fetch targets when dropdown opens
  useEffect(() => {
    if (!open) return;
    api
      .getTargets()
      .then((res) => setTargets(res.targets))
      .catch(() => {});
  }, [open]);

  function switchCampaign(target: Target) {
    setActiveTarget(target);
    setOpen(false);
    router.push("/campaign/c2");
  }

  return (
    <header className="sticky top-0 z-20 flex h-14 items-center justify-between border-b border-border bg-bg-secondary px-6">
      {/* Left — active campaign info */}
      <div className="flex items-center gap-4">
        {activeTarget ? (
          <div ref={ref} className="relative flex items-center">
            <button
              onClick={() => setOpen(!open)}
              className="flex items-center gap-2 rounded-md px-2 py-1 transition-colors hover:bg-bg-surface"
            >
              <span className="text-sm text-text-secondary">Campaign:</span>
              <span className="text-sm font-medium text-text-primary">
                {activeTarget.base_domain}
              </span>
              <ChevronDown className="h-3.5 w-3.5 text-text-muted" />
            </button>
            {open && (
              <div className="absolute left-0 top-full mt-1 w-64 rounded-lg border border-border bg-bg-secondary shadow-lg">
                {targets.map((t) => (
                  <button
                    key={t.id}
                    onClick={() => switchCampaign(t)}
                    className={`flex w-full items-center gap-2 px-3 py-2 text-left text-sm transition-colors hover:bg-bg-surface ${
                      t.id === activeTarget.id
                        ? "text-accent"
                        : "text-text-primary"
                    }`}
                  >
                    <span className="truncate">{t.base_domain}</span>
                    <span className="ml-auto text-xs text-text-muted">
                      {t.company_name}
                    </span>
                  </button>
                ))}
              </div>
            )}
            {currentPhase && (
              <span className="ml-2 rounded bg-bg-surface px-2 py-0.5 text-xs text-accent">
                {currentPhase}
              </span>
            )}
          </div>
        ) : (
          <span className="text-sm text-text-muted">No active campaign</span>
        )}
      </div>

      {/* Right — alerts + connection indicator */}
      <div className="flex items-center gap-3">
        <AlertDropdown />
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
