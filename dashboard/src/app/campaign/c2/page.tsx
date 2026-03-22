"use client";

import { useEffect, useState, useRef } from "react";
import { Activity, Settings } from "lucide-react";
import AssetTree, { type TreeNode } from "@/components/c2/AssetTree";
import WorkerConsole from "@/components/c2/WorkerConsole";
import WorkerFeed from "@/components/c2/WorkerFeed";
import StatusBoard from "@/components/c2/StatusBoard";
import SettingsDrawer from "@/components/c2/SettingsDrawer";
import DiffTimeline from "@/components/c2/DiffTimeline";
import ScopeDriftAlerts from "@/components/c2/ScopeDriftAlerts";
import QueueHealthWidget from "@/components/c2/QueueHealthWidget";
import { useEventStream } from "@/hooks/useEventStream";
import { useCampaignStore } from "@/stores/campaign";
import { api } from "@/lib/api";
import type { JobState } from "@/types/schema";

function buildTree(
  baseDomain: string,
  assets: {
    id: number;
    asset_type: string;
    asset_value: string;
    source_tool: string | null;
    locations: {
      id: number;
      port: number;
      protocol: string | null;
      service: string | null;
      state: string | null;
    }[];
  }[],
): TreeNode[] {
  const root: TreeNode = {
    id: "root",
    label: baseDomain,
    type: "domain",
    children: [],
  };
  for (const asset of assets) {
    const node: TreeNode = {
      id: `asset-${asset.id}`,
      label: asset.asset_value,
      type: (asset.asset_type === "subdomain" || asset.asset_type === "ip"
        ? asset.asset_type
        : "subdomain") as TreeNode["type"],
      children: asset.locations.map((loc) => ({
        id: `loc-${loc.id}`,
        label: `${loc.port}/${loc.protocol ?? "tcp"}`,
        type: "port" as const,
        meta: { service: loc.service },
      })),
    };
    root.children!.push(node);
  }
  return [root];
}

export default function C2Page() {
  const { activeTarget } = useCampaignStore();
  const { events } = useEventStream(activeTarget?.id ?? null);
  const [jobs, setJobs] = useState<JobState[]>([]);
  const [treeRoots, setTreeRoots] = useState<TreeNode[]>([]);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const lastMergedIdx = useRef(0);

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
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [activeTarget]);

  // Load initial asset tree from API
  useEffect(() => {
    if (!activeTarget) return;
    lastMergedIdx.current = 0;
    api
      .getAssets(activeTarget.id)
      .then((res) =>
        setTreeRoots(buildTree(activeTarget.base_domain, res.assets)),
      )
      .catch(() => {});
  }, [activeTarget]);

  // Merge SSE NEW_ASSET events into the tree
  useEffect(() => {
    if (!activeTarget || events.length === 0) return;
    const newEvents = events.slice(lastMergedIdx.current);
    lastMergedIdx.current = events.length;
    const assetEvents = newEvents.filter((e) => e.event === "NEW_ASSET");
    if (assetEvents.length === 0) return;
    setTreeRoots((prev) => {
      if (prev.length === 0) return prev;
      const root = {
        ...prev[0],
        children: [...(prev[0].children ?? [])],
      };
      for (const evt of assetEvents) {
        const d = evt as Record<string, unknown>;
        root.children!.push({
          id: `sse-${String(d.asset_value)}-${Date.now()}`,
          label: String(d.asset_value ?? ""),
          type: (String(d.asset_type ?? "subdomain") === "ip"
            ? "ip"
            : "subdomain") as TreeNode["type"],
        });
      }
      return [root];
    });
  }, [events, activeTarget]);

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
        <button
          onClick={() => setSettingsOpen(true)}
          className="ml-auto rounded p-1.5 text-text-muted transition-colors hover:bg-bg-surface hover:text-text-primary"
          title="Settings"
        >
          <Settings className="h-4 w-4" />
        </button>
      </div>

      {/* Phase progress bar */}
      <PhaseProgress currentPhase={jobs[0]?.current_phase ?? null} />

      {/* Running job status cards */}
      <StatusBoard jobs={jobs} />

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Left -- Asset tree */}
        <div className="lg:col-span-1">
          <div className="rounded-lg border border-border bg-bg-secondary p-4">
            <h2 className="mb-3 text-sm font-semibold text-text-secondary">
              Asset Tree
            </h2>
            <AssetTree roots={treeRoots} />
          </div>
        </div>

        {/* Right -- Workers + Feed */}
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

      {/* Diff Timeline + Scope Drift + Queue Health */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <DiffTimeline events={events} />
        <ScopeDriftAlerts events={events} />
      </div>
      <QueueHealthWidget />

      {/* Settings drawer */}
      <SettingsDrawer
        open={settingsOpen}
        onClose={() => setSettingsOpen(false)}
        targetId={activeTarget.id}
        currentProfile={activeTarget.target_profile}
      />
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
