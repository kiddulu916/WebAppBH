"use client";

import { useEffect, useState, useCallback, useMemo, useRef } from "react";
import { Activity, Settings, RotateCcw } from "lucide-react";
import PipelineGrid from "@/components/pipeline/PipelineGrid";
import WorkerDetailDrawer from "@/components/pipeline/WorkerDetailDrawer";
import { WORKER_STAGE_COUNTS } from "@/types/schema";
import type { PipelineWorkerState } from "@/types/schema";
import { WORKER_STAGES } from "@/lib/worker-stages";
import SystemPulse from "@/components/c2/SystemPulse";
import CampaignTimeline from "@/components/c2/CampaignTimeline";
import SettingsDrawer from "@/components/c2/SettingsDrawer";
import DiffTimeline from "@/components/c2/DiffTimeline";
import ScopeDriftAlerts from "@/components/c2/ScopeDriftAlerts";
import AssetTree, { type TreeNode } from "@/components/c2/AssetTree";
import AssetDetailDrawer from "@/components/c2/AssetDetailDrawer";
import { useCampaignStore } from "@/stores/campaign";
import { api, type PlaybookRow, type AssetWithLocations } from "@/lib/api";
import type { JobState } from "@/types/schema";

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
  const [assets, setAssets] = useState<AssetWithLocations[]>([]);
  const [selectedAsset, setSelectedAsset] = useState<AssetWithLocations | null>(null);
  const processedEventCountRef = useRef(0);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [rerunOpen, setRerunOpen] = useState(false);
  const [rerunMode, setRerunMode] = useState<"menu" | "pick">("menu");
  const [playbooks, setPlaybooks] = useState<PlaybookRow[]>([]);
  const [rerunning, setRerunning] = useState(false);
  const [selectedWorker, setSelectedWorker] = useState<string | null>(null);

  // Merge store jobs and local jobs (local poll takes priority for freshness)
  const jobs = localJobs.length > 0 ? localJobs : storeJobs;

  const hasActiveJobs = jobs.some((j) =>
    ["RUNNING", "QUEUED", "PAUSED"].includes(j.status),
  );

  const workerJobCards = useMemo(() => {
    const seen = new Set<string>();
    const result: Array<{
      key: string;
      containerName: string;
      status: string;
      currentPhase: string | null;
      lastTool: string | null;
    }> = [];
    for (const job of jobs) {
      const key = job.container_name
        .replace(/^webbh-/, "")
        .replace(/-t\d+$/, "")
        .replace(/-/g, "_");
      if (!seen.has(key)) {
        seen.add(key);
        result.push({
          key,
          containerName: job.container_name,
          status: job.status,
          currentPhase: job.current_phase,
          lastTool: job.last_tool_executed,
        });
      }
    }
    return result;
  }, [jobs]);

  const treeRoots = useMemo<TreeNode[]>(
    () =>
      assets.map((a) => ({
        id: `asset-${a.id}`,
        label: a.asset_value,
        type: (["domain", "subdomain", "ip", "port", "endpoint", "param"].includes(
          a.asset_type,
        )
          ? a.asset_type
          : "subdomain") as TreeNode["type"],
      })),
    [assets],
  );

  const handleAssetSelect = useCallback(
    (nodeId: string) => {
      const id = parseInt(nodeId.replace("asset-", ""), 10);
      setSelectedAsset(assets.find((a) => a.id === id) ?? null);
    },
    [assets],
  );

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

  const handleWorkerControl = useCallback(async (containerName: string, action: "pause" | "stop" | "restart" | "unpause") => {
    try {
      await api.controlWorker(containerName, action);
      await refreshJobs();
    } catch {
      /* noop — toast shown by api.request() */
    }
  }, [refreshJobs]);

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

  useEffect(() => {
    if (!activeTarget) return;
    refreshJobs();
    const interval = setInterval(refreshJobs, 10_000);
    return () => clearInterval(interval);
  }, [activeTarget, refreshJobs]);

  useEffect(() => {
    if (!activeTarget) { setAssets([]); processedEventCountRef.current = 0; return; }
    api.getAllAssets(activeTarget.id).then(setAssets).catch(() => {});
  }, [activeTarget]);

  /* ---- Merge SSE events ---- */
  useEffect(() => {
    if (!activeTarget || events.length === 0) return;
    const newEvents = events.slice(processedEventCountRef.current);
    processedEventCountRef.current = events.length;
    if (newEvents.length === 0) return;

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
      setLocalJobs([]);
      setJobs([]);
    }

    // Handle NEW_ASSET — add to local asset tree
    for (const e of newEvents) {
      if (e.event !== "NEW_ASSET") continue;
      const value = e.asset_value as string | undefined;
      const type = e.asset_type as string | undefined;
      if (!value) continue;
      setAssets((prev) => {
        if (prev.some((a) => a.asset_value === value)) return prev;
        return [
          ...prev,
          {
            id: -Date.now(),
            target_id: activeTarget.id,
            asset_type: type ?? "subdomain",
            asset_value: value,
            source_tool: null,
            created_at: (e.timestamp as string | undefined) ?? new Date().toISOString(),
            updated_at: null,
            tech: null,
            scope_classification: "pending",
            associated_with_id: null,
            association_method: null,
            locations: [],
            observations: [],
          },
        ];
      });
    }
  }, [events, activeTarget, setJobs]);

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

      {/* Asset Tree */}
      {assets.length > 0 && (
        <div data-testid="c2-asset-tree" className="rounded-lg border border-border bg-bg-secondary p-4">
          <div className="section-label mb-3">ASSETS ({assets.length})</div>
          <AssetTree roots={treeRoots} onSelect={handleAssetSelect} />
        </div>
      )}

      {/* Worker Job Cards */}
      {workerJobCards.length > 0 && (
        <div data-testid="c2-worker-grid" className="rounded-lg border border-border bg-bg-secondary p-4">
          <div className="section-label mb-3">WORKER JOBS</div>
          <div className="grid grid-cols-2 gap-3">
            {workerJobCards.map(({ key, containerName, status, currentPhase }) => (
              <div
                key={key}
                data-testid={`worker-card-${key}`}
                className="rounded-lg border border-border bg-bg-tertiary p-3"
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="font-mono text-sm text-text-primary capitalize">
                    {key.replace(/_/g, " ")}
                  </span>
                  <span className={`text-xs font-semibold ${
                    status === "RUNNING" ? "text-neon-orange" :
                    status === "COMPLETED" ? "text-neon-green" :
                    status === "FAILED" ? "text-danger" :
                    status === "PAUSED" ? "text-warning" :
                    "text-text-muted"
                  }`}>
                    {status}
                  </span>
                </div>
                {currentPhase && (
                  <div className="text-xs text-text-muted mb-2">
                    Phase: <span className="font-mono text-text-secondary">{currentPhase}</span>
                  </div>
                )}
                <div className="flex gap-2">
                  {(status === "RUNNING") && (
                    <>
                      <button
                        data-testid="worker-pause-btn"
                        onClick={() => handleWorkerControl(containerName, "pause")}
                        className="rounded px-2 py-0.5 text-xs border border-border text-text-muted hover:text-text-primary hover:border-text-primary transition-colors"
                      >
                        Pause
                      </button>
                      <button
                        data-testid="worker-stop-btn"
                        onClick={() => handleWorkerControl(containerName, "stop")}
                        className="rounded px-2 py-0.5 text-xs border border-danger/40 text-danger hover:bg-danger/10 transition-colors"
                      >
                        Stop
                      </button>
                    </>
                  )}
                  {status === "PAUSED" && (
                    <button
                      data-testid="worker-resume-btn"
                      onClick={() => handleWorkerControl(containerName, "unpause")}
                      className="rounded px-2 py-0.5 text-xs border border-neon-green/40 text-neon-green hover:bg-neon-green/10 transition-colors"
                    >
                      Resume
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Campaign Timeline — full width */}
      <div data-testid="c2-timeline" className="rounded-lg border border-border bg-bg-secondary p-4">
        <div className="section-label mb-3">CAMPAIGN TIMELINE</div>
        <CampaignTimeline jobs={jobs} />
      </div>

      {/* System Pulse */}
      <SystemPulse />

      {/* Diff Timeline + Scope Drift Alerts */}
      <div className="grid grid-cols-2 gap-5">
        <DiffTimeline events={events} />
        <ScopeDriftAlerts events={events} />
      </div>

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

      {/* Asset Detail Drawer */}
      <AssetDetailDrawer
        asset={selectedAsset}
        onClose={() => setSelectedAsset(null)}
      />
    </div>
  );
}
