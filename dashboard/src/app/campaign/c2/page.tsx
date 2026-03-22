"use client";

import { useEffect, useState, useRef, useCallback } from "react";
import { Activity, Settings } from "lucide-react";
import AssetTree, { type TreeNode } from "@/components/c2/AssetTree";
import PhasePipeline from "@/components/c2/PhasePipeline";
import WorkerGrid from "@/components/c2/WorkerGrid";
import SystemPulse from "@/components/c2/SystemPulse";
import AssetDetailDrawer from "@/components/c2/AssetDetailDrawer";
import SettingsDrawer from "@/components/c2/SettingsDrawer";
import DiffTimeline from "@/components/c2/DiffTimeline";
import ScopeDriftAlerts from "@/components/c2/ScopeDriftAlerts";
import QueueHealthWidget from "@/components/c2/QueueHealthWidget";
import { useCampaignStore } from "@/stores/campaign";
import { api, type AssetWithLocations } from "@/lib/api";
import type { JobState } from "@/types/schema";

/* ------------------------------------------------------------------ */
/* Build the asset tree from flat API records                          */
/* ------------------------------------------------------------------ */

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

/* ------------------------------------------------------------------ */
/* C2 Console Page                                                     */
/* ------------------------------------------------------------------ */

export default function C2Page() {
  const activeTarget = useCampaignStore((s) => s.activeTarget);
  const events = useCampaignStore((s) => s.events);
  const storeJobs = useCampaignStore((s) => s.jobs);
  const setJobs = useCampaignStore((s) => s.setJobs);

  const [localJobs, setLocalJobs] = useState<JobState[]>([]);
  const [treeRoots, setTreeRoots] = useState<TreeNode[]>([]);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [selectedAsset, setSelectedAsset] =
    useState<AssetWithLocations | null>(null);
  const [allAssets, setAllAssets] = useState<AssetWithLocations[]>([]);
  const lastMergedIdx = useRef(0);

  // Merge store jobs and local jobs (local poll takes priority for freshness)
  const jobs = localJobs.length > 0 ? localJobs : storeJobs;

  // Derive completed phases from jobs
  const completedPhases = jobs
    .filter(
      (j) => j.status === "COMPLETED" && j.current_phase,
    )
    .map((j) => j.current_phase!);

  const currentPhase =
    jobs.find((j) => j.status === "RUNNING")?.current_phase ?? null;

  /* ---- Fetch job states periodically ---- */
  useEffect(() => {
    if (!activeTarget) return;
    let cancelled = false;

    async function poll() {
      try {
        const res = await api.getStatus(activeTarget!.id);
        if (!cancelled) {
          setLocalJobs(res.jobs);
          setJobs(res.jobs);
        }
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
  }, [activeTarget, setJobs]);

  /* ---- Load initial asset tree from API ---- */
  useEffect(() => {
    if (!activeTarget) return;
    lastMergedIdx.current = 0;
    api
      .getAssets(activeTarget.id)
      .then((res) => {
        setAllAssets(res.assets);
        setTreeRoots(buildTree(activeTarget.base_domain, res.assets));
      })
      .catch(() => {});
  }, [activeTarget]);

  /* ---- Merge SSE NEW_ASSET events into the tree ---- */
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

  /* ---- Handle asset selection from tree ---- */
  const handleAssetSelect = useCallback(
    (nodeId: string) => {
      // Find the asset matching this tree node
      const assetIdStr = nodeId.replace("asset-", "");
      const assetId = parseInt(assetIdStr, 10);
      if (isNaN(assetId)) return;
      const found = allAssets.find((a) => a.id === assetId);
      if (found) setSelectedAsset(found);
    },
    [allAssets],
  );

  /* ---- No active campaign ---- */
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
    <div className="space-y-5">
      {/* Page header */}
      <div className="flex items-center gap-3">
        <Activity className="h-5 w-5 text-accent" />
        <h1 className="text-2xl font-bold text-text-primary">C2 Console</h1>
        <span className="rounded bg-bg-surface px-2 py-0.5 font-mono text-xs text-accent">
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

      {/* Phase Pipeline */}
      <PhasePipeline
        currentPhase={currentPhase}
        completedPhases={completedPhases}
      />

      {/* Main content: Asset Tree (1/3) + Worker Grid (2/3) */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
        {/* Left -- Asset Tree */}
        <div className="lg:col-span-1">
          <div className="rounded-lg border border-border bg-bg-secondary p-4">
            <div className="section-label mb-3">ASSET TREE</div>
            <div className="max-h-[600px] overflow-y-auto">
              <AssetTree
                roots={treeRoots}
                onSelect={handleAssetSelect}
              />
            </div>
          </div>
        </div>

        {/* Right -- Worker Grid */}
        <div className="lg:col-span-2">
          <div className="rounded-lg border border-border bg-bg-secondary p-4">
            <WorkerGrid jobs={jobs} events={events} />
          </div>
        </div>
      </div>

      {/* System Pulse (conditional on systemPulseOpen) */}
      <SystemPulse />

      {/* Diff Timeline + Scope Drift Alerts */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <DiffTimeline events={events} />
        <ScopeDriftAlerts events={events} />
      </div>

      {/* Queue Health */}
      <QueueHealthWidget />

      {/* Asset Detail Drawer */}
      <AssetDetailDrawer
        asset={selectedAsset}
        onClose={() => setSelectedAsset(null)}
      />

      {/* Settings Drawer */}
      <SettingsDrawer
        open={settingsOpen}
        onClose={() => setSettingsOpen(false)}
        targetId={activeTarget.id}
        currentProfile={activeTarget.target_profile}
      />
    </div>
  );
}
