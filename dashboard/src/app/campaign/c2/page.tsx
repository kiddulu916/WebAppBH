"use client";

import { useEffect, useState, useRef, useCallback } from "react";
import { Activity, Settings, RotateCcw } from "lucide-react";
import AssetTree, { type TreeNode } from "@/components/c2/AssetTree";
import PipelineGrid from "@/components/pipeline/PipelineGrid";
import WorkerDetailDrawer from "@/components/pipeline/WorkerDetailDrawer";
import { WORKER_STAGE_COUNTS } from "@/types/schema";
import type { PipelineWorkerState } from "@/types/schema";
import { WORKER_STAGES } from "@/lib/worker-stages";
import SystemPulse from "@/components/c2/SystemPulse";
import WorkerHealthPanel from "@/components/c2/WorkerHealthPanel";
import CampaignTimeline from "@/components/c2/CampaignTimeline";
import AssetDetailDrawer from "@/components/c2/AssetDetailDrawer";
import SettingsDrawer from "@/components/c2/SettingsDrawer";
import DiffTimeline from "@/components/c2/DiffTimeline";
import ScopeDriftAlerts from "@/components/c2/ScopeDriftAlerts";
import QueueHealthWidget from "@/components/c2/QueueHealthWidget";
import { useCampaignStore } from "@/stores/campaign";
import { api, type AssetWithLocations, type PlaybookRow } from "@/lib/api";
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
/* Map JobState[] → PipelineWorkerState record for PipelineGrid        */
/* ------------------------------------------------------------------ */

function statusPriority(s: string): number {
  switch (s) {
    case "running": return 4;
    case "queued": return 3;
    case "failed": return 2;
    case "complete": return 1;
    default: return 0;
  }
}

function jobsToWorkerStates(jobs: JobState[]): Record<string, PipelineWorkerState> {
  const states: Record<string, PipelineWorkerState> = {};
  for (const job of jobs) {
    const workerKey = job.container_name
      .replace(/^webbh-/, "")
      .replace(/-t\d+$/, "")
      .replace(/-/g, "_");

    const status = (() => {
      switch (job.status) {
        case "RUNNING": return "running" as const;
        case "QUEUED": return "queued" as const;
        case "COMPLETED": return "complete" as const;
        case "FAILED": return "failed" as const;
        case "PAUSED": return "running" as const;
        default: return "pending" as const;
      }
    })();

    const existing = states[workerKey];
    if (!existing || statusPriority(status) > statusPriority(existing.status)) {
      states[workerKey] = {
        status,
        current_section_id: job.current_phase ?? undefined,
        last_tool_executed: job.last_tool_executed ?? undefined,
        started_at: job.started_at ?? undefined,
        completed_at: job.completed_at ?? undefined,
        total_stages: WORKER_STAGE_COUNTS[workerKey] ?? 0,
      };
    }
  }
  return states;
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
  const [rerunOpen, setRerunOpen] = useState(false);
  const [rerunMode, setRerunMode] = useState<"menu" | "pick">("menu");
  const [playbooks, setPlaybooks] = useState<PlaybookRow[]>([]);
  const [rerunning, setRerunning] = useState(false);
  const [selectedAsset, setSelectedAsset] =
    useState<AssetWithLocations | null>(null);
  const [allAssets, setAllAssets] = useState<AssetWithLocations[]>([]);
  const [selectedWorker, setSelectedWorker] = useState<string | null>(null);
  const lastMergedIdx = useRef(0);

  // Merge store jobs and local jobs (local poll takes priority for freshness)
  const jobs = localJobs.length > 0 ? localJobs : storeJobs;

  const hasActiveJobs = jobs.some((j) =>
    ["RUNNING", "QUEUED", "PAUSED"].includes(j.status),
  );

  async function handleRerun(playbookName: string) {
    if (!activeTarget) return;
    setRerunning(true);
    try {
      await api.rerun(activeTarget.id, playbookName);
      setRerunOpen(false);
      setRerunMode("menu");
    } catch {
      // toast shown by api.request()
    } finally {
      setRerunning(false);
    }
  }

  function openPlaybookPicker() {
    setRerunMode("pick");
    api.getPlaybooks().then((res) => setPlaybooks(res)).catch(() => {});
  }

  /* ---- Fetch job states periodically ---- */
  const refreshJobs = useCallback(async () => {
    if (!activeTarget) return;
    try {
      const res = await api.getStatus(activeTarget.id);
      setLocalJobs(res.jobs);
      setJobs(res.jobs);
    } catch {
      /* noop */
    }
  }, [activeTarget, setJobs]);

  useEffect(() => {
    if (!activeTarget) return;
    refreshJobs();
    const interval = setInterval(refreshJobs, 10_000);
    return () => clearInterval(interval);
  }, [activeTarget, refreshJobs]);

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
    if (assetEvents.length > 0) {
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
    }

    // Handle KILL_ALL — refresh jobs to show KILLED statuses
    const killEvents = newEvents.filter((e) => e.event === "KILL_ALL");
    if (killEvents.length > 0) {
      api.getStatus(activeTarget.id).then((res) => {
        setLocalJobs(res.jobs);
        setJobs(res.jobs);
      }).catch(() => {});
    }

    // Handle RERUN_STARTED — reset pipeline, clear jobs
    const rerunEvents = newEvents.filter((e) => e.event === "RERUN_STARTED");
    if (rerunEvents.length > 0) {
      setLocalJobs([]);
      setJobs([]);
    }

    // Handle CLEAN_SLATE — reset everything
    const cleanEvents = newEvents.filter((e) => e.event === "CLEAN_SLATE");
    if (cleanEvents.length > 0) {
      setTreeRoots([]);
      setAllAssets([]);
      setLocalJobs([]);
      setJobs([]);
    }
  }, [events, activeTarget, setJobs]);

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
      <div data-testid="c2-empty-state" className="flex h-64 items-center justify-center">
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
        <div className="ml-auto flex items-center gap-1">
          {/* Rerun Popover */}
          <div className="relative">
            <button
              onClick={() => { setRerunOpen(!rerunOpen); setRerunMode("menu"); }}
              disabled={hasActiveJobs}
              className="flex items-center gap-1 rounded px-2 py-1 text-xs font-medium text-accent transition-colors hover:bg-accent/10 disabled:cursor-not-allowed disabled:opacity-40"
              title={hasActiveJobs ? "Kill current run first" : "Rerun target"}
            >
              <RotateCcw className="h-3.5 w-3.5" />
              Rerun
            </button>
            {rerunOpen && !hasActiveJobs && (
              <div className="absolute right-0 top-full z-30 mt-1 w-56 rounded-md border border-border bg-bg-secondary shadow-lg animate-fade-in">
                {rerunMode === "menu" ? (
                  <div className="p-1">
                    <button
                      onClick={() => handleRerun(activeTarget!.last_playbook ?? "wide_recon")}
                      disabled={rerunning}
                      className="flex w-full flex-col items-start rounded px-3 py-2 text-left transition-colors hover:bg-bg-surface disabled:opacity-50"
                    >
                      <span className="text-xs font-medium text-text-primary">Same Playbook</span>
                      <span className="text-[10px] text-text-muted font-mono">
                        {activeTarget!.last_playbook ?? "wide_recon"}
                      </span>
                    </button>
                    <button
                      onClick={openPlaybookPicker}
                      className="flex w-full items-start rounded px-3 py-2 text-left text-xs font-medium text-text-primary transition-colors hover:bg-bg-surface"
                    >
                      Change Playbook
                    </button>
                  </div>
                ) : (
                  <div className="max-h-64 overflow-y-auto p-1">
                    {playbooks.map((pb) => (
                      <button
                        key={pb.id ?? pb.name}
                        onClick={() => handleRerun(pb.name)}
                        disabled={rerunning}
                        className="flex w-full flex-col items-start rounded px-3 py-2 text-left transition-colors hover:bg-bg-surface disabled:opacity-50"
                      >
                        <span className="text-xs font-medium text-text-primary">{pb.name}</span>
                        {pb.description && (
                          <span className="text-[10px] text-text-muted line-clamp-1">{pb.description}</span>
                        )}
                      </button>
                    ))}
                    {playbooks.length === 0 && (
                      <span className="block px-3 py-2 text-xs text-text-muted">Loading...</span>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
          <button
            onClick={() => setSettingsOpen(true)}
            className="rounded p-1.5 text-text-muted transition-colors hover:bg-bg-surface hover:text-text-primary"
            title="Settings"
          >
            <Settings className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* Pipeline Grid */}
      <div data-testid="c2-phase-pipeline" className="rounded-lg border border-border bg-bg-secondary p-4">
        <div className="section-label mb-3">PIPELINE</div>
        <PipelineGrid
          workerStates={jobsToWorkerStates(jobs)}
          onWorkerClick={setSelectedWorker}
        />
      </div>

      {/* Main content: Asset Tree (1/3) + Worker Grid (2/3) */}
      <div className="grid grid-cols-3 gap-5">
        {/* Left -- Asset Tree */}
        <div className="col-span-1" data-testid="c2-asset-tree">
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

        {/* Right -- Events placeholder */}
        <div className="col-span-2" data-testid="c2-worker-grid">
          <div className="rounded-lg border border-border bg-bg-secondary p-4">
            <div className="section-label mb-3">EVENTS</div>
            <div className="text-sm text-text-muted">Event feed — see live terminal below</div>
          </div>
        </div>
      </div>

      {/* Worker Health */}
      <WorkerHealthPanel />

      {/* System Pulse (conditional on systemPulseOpen) */}
      <SystemPulse />

      {/* Campaign Timeline */}
      <div data-testid="c2-timeline">
        <CampaignTimeline jobs={jobs} />
      </div>

      {/* Diff Timeline + Scope Drift Alerts */}
      <div className="grid grid-cols-2 gap-5">
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

      {/* Worker Detail Drawer */}
      {selectedWorker && (
        <WorkerDetailDrawer
          worker={selectedWorker}
          state={jobsToWorkerStates(jobs)[selectedWorker] || { status: "pending" }}
          stages={WORKER_STAGES[selectedWorker] || []}
          findingCount={0}
          onClose={() => setSelectedWorker(null)}
        />
      )}

      {/* Settings Drawer */}
      <SettingsDrawer
        open={settingsOpen}
        onClose={() => setSettingsOpen(false)}
        targetId={activeTarget.id}
        currentProfile={activeTarget.target_profile}
        hasActiveJobs={hasActiveJobs}
      />
    </div>
  );
}
