"use client";

import { useEffect, useState } from "react";
import { Activity } from "lucide-react";
import AssetTree, { type TreeNode } from "@/components/c2/AssetTree";
import WorkerConsole from "@/components/c2/WorkerConsole";
import WorkerFeed from "@/components/c2/WorkerFeed";
import { useEventStream } from "@/hooks/useEventStream";
import { useCampaignStore } from "@/stores/campaign";
import { api } from "@/lib/api";
import type { JobState } from "@/types/schema";

export default function C2Page() {
  const { activeTarget } = useCampaignStore();
  const { events } = useEventStream(activeTarget?.id ?? null);
  const [jobs, setJobs] = useState<JobState[]>([]);

  // Fetch job states periodically
  useEffect(() => {
    if (!activeTarget) return;
    let cancelled = false;

    async function poll() {
      try {
        const res = await api.getStatus(activeTarget!.id);
        if (!cancelled) setJobs(res.jobs);
      } catch {
        /* noop */
      }
    }

    poll();
    const interval = setInterval(poll, 10_000);
    return () => { cancelled = true; clearInterval(interval); };
  }, [activeTarget]);

  // Build demo tree from SSE events (real data will come from DB queries later)
  const treeRoots: TreeNode[] = activeTarget
    ? [
        {
          id: "root",
          label: activeTarget.base_domain,
          type: "domain",
          children: events
            .filter((e) => e.event === "NEW_ASSET")
            .map((e, i) => ({
              id: `asset-${i}`,
              label: String((e as Record<string, unknown>).asset_value ?? ""),
              type: (String((e as Record<string, unknown>).asset_type ?? "subdomain")) as TreeNode["type"],
            })),
        },
      ]
    : [];

  if (!activeTarget) {
    return (
      <div className="flex h-64 items-center justify-center">
        <p className="text-text-muted">
          No active campaign. Launch one from the{" "}
          <a href="/campaign" className="text-accent underline">
            Campaign
          </a>{" "}
          page.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Activity className="h-5 w-5 text-accent" />
        <h1 className="text-2xl font-bold text-text-primary">C2 Console</h1>
        <span className="rounded bg-bg-surface px-2 py-0.5 text-xs text-accent">
          {activeTarget.base_domain}
        </span>
      </div>

      {/* Phase progress bar */}
      <PhaseProgress currentPhase={jobs[0]?.current_phase ?? null} />

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Left — Asset tree */}
        <div className="lg:col-span-1">
          <div className="rounded-lg border border-border bg-bg-secondary p-4">
            <h2 className="mb-3 text-sm font-semibold text-text-secondary">
              Asset Tree
            </h2>
            <AssetTree roots={treeRoots} />
          </div>
        </div>

        {/* Right — Workers + Feed */}
        <div className="space-y-4 lg:col-span-2">
          <div className="rounded-lg border border-border bg-bg-secondary p-4">
            <h2 className="mb-3 text-sm font-semibold text-text-secondary">
              Worker Management
            </h2>
            <WorkerConsole jobs={jobs} />
          </div>

          <WorkerFeed events={events} />
        </div>
      </div>
    </div>
  );
}

/* ---- Phase progress bar ---- */

const PHASES = ["RECON", "VULN", "EXPLOIT"] as const;

function PhaseProgress({ currentPhase }: { currentPhase: string | null }) {
  const activeIdx = currentPhase
    ? PHASES.findIndex((p) => currentPhase.toUpperCase().includes(p))
    : 0;

  return (
    <div className="flex items-center gap-2">
      {PHASES.map((phase, i) => (
        <div key={phase} className="flex items-center gap-2">
          {i > 0 && (
            <div
              className={`h-px w-6 ${i <= activeIdx ? "bg-accent" : "bg-border"}`}
            />
          )}
          <span
            className={`rounded-full px-3 py-1 text-xs font-medium ${
              i < activeIdx
                ? "bg-success/20 text-success"
                : i === activeIdx
                  ? "bg-accent/20 text-accent"
                  : "bg-bg-surface text-text-muted"
            }`}
          >
            {phase}
          </span>
        </div>
      ))}
    </div>
  );
}
