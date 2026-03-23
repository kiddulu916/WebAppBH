"use client";

import { useEffect, useState, useRef } from "react";
import { useRouter } from "next/navigation";
import { ChevronDown, Wifi, WifiOff, Command, Power } from "lucide-react";
import { api } from "@/lib/api";
import { useCampaignStore } from "@/stores/campaign";
import { useUIStore } from "@/stores/ui";
import AlertDropdown from "@/components/layout/AlertDropdown";
import type { Target } from "@/types/schema";

export default function TopBar() {
  const router = useRouter();
  const { connected, activeTarget, currentPhase, jobs, setActiveTarget } =
    useCampaignStore();
  const setCommandPaletteOpen = useUIStore((s) => s.setCommandPaletteOpen);
  const [open, setOpen] = useState(false);
  const [targets, setTargets] = useState<Target[]>([]);
  const ref = useRef<HTMLDivElement>(null);
  const [killConfirmOpen, setKillConfirmOpen] = useState(false);
  const [killing, setKilling] = useState(false);

  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, []);

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

  async function handleKill() {
    setKilling(true);
    try {
      await api.kill();
      setKillConfirmOpen(false);
    } catch {
      /* error handled by API client */
    } finally {
      setKilling(false);
    }
  }

  const runningWorkers = jobs.filter((j) => j.status === "RUNNING").length;

  return (
    <header className="sticky top-0 z-20 flex h-11 items-center justify-between border-b border-border bg-bg-secondary/80 backdrop-blur-sm px-4">
      {/* Left — campaign context */}
      <div className="flex items-center gap-3">
        {activeTarget ? (
          <div ref={ref} className="relative flex items-center gap-2">
            <button
              onClick={() => setOpen(!open)}
              className="flex items-center gap-1.5 rounded px-2 py-1 text-xs transition-colors hover:bg-bg-surface"
            >
              <span className="text-text-muted">Target:</span>
              <span className="font-mono font-medium text-neon-orange">
                {activeTarget.base_domain}
              </span>
              <ChevronDown className="h-3 w-3 text-text-muted" />
            </button>
            {open && (
              <div className="absolute left-0 top-full mt-1 w-60 rounded-md border border-border bg-bg-secondary shadow-lg animate-fade-in">
                {targets.map((t) => (
                  <button
                    key={t.id}
                    onClick={() => switchCampaign(t)}
                    className={`flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs transition-colors hover:bg-bg-surface ${
                      t.id === activeTarget.id ? "text-neon-orange" : "text-text-primary"
                    }`}
                  >
                    <span className="truncate font-mono">{t.base_domain}</span>
                    <span className="ml-auto text-text-muted">{t.company_name}</span>
                  </button>
                ))}
              </div>
            )}
            {currentPhase && (
              <span className="rounded bg-neon-orange-glow px-2 py-0.5 text-[10px] font-medium text-neon-orange">
                {currentPhase}
              </span>
            )}
            {runningWorkers > 0 && (
              <span className="flex items-center gap-1 text-[10px] text-neon-green">
                <span className="relative flex h-1.5 w-1.5">
                  <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-neon-green opacity-60" />
                  <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-neon-green" />
                </span>
                {runningWorkers} running
              </span>
            )}
          </div>
        ) : (
          <span className="text-xs text-text-muted">No active campaign</span>
        )}
      </div>

      {/* Right — cmd-k + alerts + connection */}
      <div className="flex items-center gap-2">
        <button
          onClick={() => setKillConfirmOpen(true)}
          className="flex items-center gap-1 rounded bg-danger/10 px-2 py-0.5 text-[10px] font-medium text-danger transition-colors hover:bg-danger/20"
          title="Kill all active operations"
        >
          <Power className="h-3 w-3" />
          <span className="hidden sm:inline">KILL</span>
        </button>
        <button
          onClick={() => setCommandPaletteOpen(true)}
          className="flex items-center gap-1 rounded border border-border px-2 py-0.5 text-[10px] text-text-muted transition-colors hover:border-border-accent hover:text-text-secondary"
        >
          <Command className="h-3 w-3" />
          <span>K</span>
        </button>
        <AlertDropdown />
        <div className="flex items-center gap-1">
          {connected ? (
            <Wifi className="h-3 w-3 text-neon-green" />
          ) : (
            <WifiOff className="h-3 w-3 text-danger" />
          )}
        </div>
      </div>
      {killConfirmOpen && (
        <>
          <div className="fixed inset-0 z-50 bg-black/60" onClick={() => setKillConfirmOpen(false)} />
          <div className="fixed left-1/2 top-1/2 z-50 w-80 -translate-x-1/2 -translate-y-1/2 rounded-lg border border-danger/30 bg-bg-secondary p-5 shadow-xl">
            <h3 className="text-sm font-semibold text-text-primary">Kill All Operations</h3>
            <p className="mt-2 text-xs text-text-muted">
              This will immediately terminate all running workers. This cannot be undone.
            </p>
            <div className="mt-4 flex justify-end gap-2">
              <button
                onClick={() => setKillConfirmOpen(false)}
                className="rounded px-3 py-1.5 text-xs text-text-muted transition-colors hover:bg-bg-surface"
              >
                Cancel
              </button>
              <button
                onClick={handleKill}
                disabled={killing}
                className="rounded bg-danger px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-danger/90 disabled:opacity-50"
              >
                {killing ? "Killing..." : "Kill All"}
              </button>
            </div>
          </div>
        </>
      )}
    </header>
  );
}
