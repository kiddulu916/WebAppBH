"use client";

import { useEffect, useState, useCallback, useMemo } from "react";
import {
  Workflow,
  CheckCircle2,
  Loader2,
  XCircle,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  Play,
  Save,
  RefreshCw,
  Clock,
  Eye,
  SkipForward,
} from "lucide-react";
import { useCampaignStore } from "@/stores/campaign";
import { api } from "@/lib/api";
import ScanTimeline from "@/components/c2/ScanTimeline";
import type { PlaybookRow, WorkerConfig } from "@/lib/api";
import type { ExecutionState, WorkerExecution, StageExecution } from "@/types/schema";
import { WORKER_DEPENDENCIES, PIPELINE_WORKER_NAMES } from "@/types/schema";
import { WORKER_STAGES } from "@/lib/worker-stages";

function formatWorkerName(name: string): string {
  return name.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

function getBlockedBy(workerName: string, workers: WorkerConfig[]): string | null {
  const deps = WORKER_DEPENDENCIES[workerName] || [];
  const disabledWorkers = new Set(workers.filter((w) => !w.enabled).map((w) => w.name));
  for (const dep of deps) {
    if (disabledWorkers.has(dep)) return dep;
  }
  return null;
}

function getTransitiveDownstream(workerName: string): Set<string> {
  const disabled = new Set<string>();
  disabled.add(workerName);
  for (const name of PIPELINE_WORKER_NAMES) {
    if (disabled.has(name)) continue;
    const deps = WORKER_DEPENDENCIES[name] || [];
    for (const dep of deps) {
      if (disabled.has(dep)) {
        disabled.add(name);
        break;
      }
    }
  }
  disabled.delete(workerName);
  return disabled;
}

function stripWstgPrefix(sectionId: string): string {
  return sectionId.replace(/^WSTG-/, "");
}

function StageRow({
  stage,
  workerName: _workerName,
  disabled,
  display,
  onToggle,
  onTimeoutChange,
}: {
  stage: { name: string; enabled: boolean; tool_timeout?: number };
  workerName: string;
  disabled: boolean;
  display: { name: string; sectionId: string } | undefined;
  onToggle: () => void;
  onTimeoutChange: (value: number) => void;
}) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div
      data-testid={`flow-stage-card-${stage.name}`}
      className={`rounded-md bg-bg-tertiary px-3 py-2${!stage.enabled ? " opacity-50" : ""}`}
    >
      <div className="flex items-center gap-3">
        <button
          type="button"
          data-testid={`flow-stage-toggle-${stage.name}`}
          onClick={onToggle}
          disabled={disabled}
          className={`relative h-4 w-7 shrink-0 rounded-full transition-colors ${
            stage.enabled && !disabled ? "bg-neon-green" : "bg-border-accent"
          } ${disabled ? "cursor-not-allowed" : "cursor-pointer"}`}
          aria-label={`Toggle ${stage.name}`}
        >
          <span
            className={`absolute top-0.5 left-0.5 h-3 w-3 rounded-full bg-white transition-transform ${
              stage.enabled && !disabled ? "translate-x-3" : ""
            }`}
          />
        </button>

        <div className="flex-1 min-w-0">
          <span className="text-xs text-text-primary">
            {display ? display.name : stage.name}
          </span>
          {display && (
            <span className="ml-2 text-xs text-text-muted">
              {stripWstgPrefix(display.sectionId)}
            </span>
          )}
        </div>

        <button
          type="button"
          onClick={() => setExpanded(!expanded)}
          className="rounded p-0.5 text-text-muted hover:text-text-primary"
          aria-label={`Expand ${stage.name} settings`}
        >
          {expanded ? (
            <ChevronUp className="h-3 w-3" />
          ) : (
            <ChevronDown className="h-3 w-3" />
          )}
        </button>
      </div>

      {expanded && (
        <div className="mt-2 flex items-center gap-3 pl-10">
          <label className="text-xs text-text-muted">Timeout:</label>
          <input
            type="range"
            min={60}
            max={1200}
            step={60}
            value={stage.tool_timeout ?? 300}
            onChange={(e) => onTimeoutChange(Number(e.target.value))}
            className="flex-1 accent-neon-orange"
          />
          <span className="w-12 text-right font-mono text-xs text-text-secondary">
            {stage.tool_timeout ?? 300}s
          </span>
        </div>
      )}
    </div>
  );
}

function WorkerCard({
  worker,
  workers,
  expanded,
  onToggleExpand,
  onToggleWorker,
  onToggleStage,
  onStageTimeoutChange,
}: {
  worker: WorkerConfig;
  workers: WorkerConfig[];
  expanded: boolean;
  onToggleExpand: () => void;
  onToggleWorker: () => void;
  onToggleStage: (stageIndex: number) => void;
  onStageTimeoutChange: (stageIndex: number, value: number) => void;
}) {
  const blockedBy = getBlockedBy(worker.name, workers);
  const isBlocked = blockedBy !== null;
  const stageDisplayInfo = WORKER_STAGES[worker.name] || [];
  const enabledCount = worker.stages.filter((s) => s.enabled).length;
  const totalCount = worker.stages.length;

  return (
    <div
      data-testid={`flow-worker-card-${worker.name}`}
      className={`rounded-lg border border-border bg-bg-secondary transition-all ${
        !worker.enabled || isBlocked ? "opacity-50" : ""
      }`}
    >
      <div className="flex items-center gap-3 p-4">
        <button
          type="button"
          data-testid={`flow-worker-toggle-${worker.name}`}
          onClick={onToggleWorker}
          disabled={isBlocked}
          className={`relative h-5 w-9 shrink-0 rounded-full transition-colors ${
            worker.enabled && !isBlocked ? "bg-neon-green" : "bg-border-accent"
          } ${isBlocked ? "cursor-not-allowed" : "cursor-pointer"}`}
          aria-label={`Toggle ${worker.name}`}
        >
          <span
            className={`absolute top-0.5 left-0.5 h-4 w-4 rounded-full bg-white transition-transform ${
              worker.enabled && !isBlocked ? "translate-x-4" : ""
            }`}
          />
        </button>

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="font-mono text-sm text-text-primary">
              {formatWorkerName(worker.name)}
            </span>
            {totalCount > 0 && (
              <span className="rounded-full bg-bg-tertiary px-2 py-0.5 text-xs font-mono text-text-muted">
                {enabledCount}/{totalCount}
              </span>
            )}
          </div>
          {isBlocked && (
            <span className="text-xs text-text-muted">
              blocked by: {formatWorkerName(blockedBy)}
            </span>
          )}
        </div>

        {totalCount > 0 && (
          <button
            type="button"
            onClick={onToggleExpand}
            className="rounded p-1 text-text-muted hover:bg-bg-tertiary hover:text-text-primary"
            aria-label={`Expand ${worker.name}`}
          >
            {expanded ? (
              <ChevronUp className="h-4 w-4" />
            ) : (
              <ChevronDown className="h-4 w-4" />
            )}
          </button>
        )}
      </div>

      {expanded && totalCount > 0 && (
        <div className="border-t border-border px-4 pb-4 pt-2 space-y-1.5">
          {worker.stages.map((stage, stageIdx) => (
            <StageRow
              key={stage.name}
              stage={stage}
              workerName={worker.name}
              disabled={!worker.enabled || isBlocked}
              display={stageDisplayInfo.find((d) => d.stageName === stage.name)}
              onToggle={() => onToggleStage(stageIdx)}
              onTimeoutChange={(val) => onStageTimeoutChange(stageIdx, val)}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function MonitorWorkerCard({
  worker,
  expanded,
  onToggleExpand,
}: {
  worker: WorkerExecution;
  expanded: boolean;
  onToggleExpand: () => void;
}) {
  const stageDisplayInfo = WORKER_STAGES[worker.name] || [];
  const completedStages = worker.stages.filter((s) => s.status === "completed").length;
  const totalStages = worker.stages.length;

  const statusIcon = {
    pending: <Clock className="h-4 w-4 text-text-muted" />,
    queued: <Clock className="h-4 w-4 text-neon-blue" />,
    running: <Loader2 className="h-4 w-4 text-neon-orange animate-spin" />,
    completed: <CheckCircle2 className="h-4 w-4 text-neon-green" />,
    failed: <XCircle className="h-4 w-4 text-danger" />,
    skipped: <SkipForward className="h-4 w-4 text-text-muted" />,
  }[worker.status];

  const statusColor = {
    pending: "text-text-muted",
    queued: "text-neon-blue",
    running: "text-neon-orange",
    completed: "text-neon-green",
    failed: "text-danger",
    skipped: "text-text-muted",
  }[worker.status];

  return (
    <div
      data-testid={`flow-monitor-worker-${worker.name}`}
      className={`rounded-lg border border-border bg-bg-secondary transition-all ${
        worker.status === "skipped" ? "opacity-50" : ""
      }`}
    >
      <div
        className="flex items-center gap-3 p-3 cursor-pointer"
        onClick={onToggleExpand}
      >
        <div className="shrink-0">{statusIcon}</div>

        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="font-mono text-sm text-text-primary">
              {formatWorkerName(worker.name)}
            </span>
            <span className={`text-xs font-semibold uppercase ${statusColor}`}>
              {worker.status}
            </span>
          </div>

          {worker.status === "running" && totalStages > 0 && (
            <div className="mt-1 flex items-center gap-2">
              <div className="flex-1 h-1.5 rounded-full bg-bg-tertiary overflow-hidden">
                <div
                  className="h-full rounded-full bg-neon-orange transition-all"
                  style={{ width: `${(completedStages / totalStages) * 100}%` }}
                />
              </div>
              <span className="text-xs font-mono text-text-muted">
                {completedStages}/{totalStages}
              </span>
            </div>
          )}

          {worker.current_tool && worker.status === "running" && (
            <span className="text-xs text-text-muted">
              Running: <span className="font-mono text-neon-orange">{worker.current_tool}</span>
            </span>
          )}

          {worker.status === "skipped" && worker.skip_reason && (
            <span className="text-xs text-text-muted">{worker.skip_reason}</span>
          )}

          {worker.status === "failed" && worker.error && (
            <span className="text-xs text-danger">{worker.error}</span>
          )}
        </div>

        {totalStages > 0 && (
          <div className="shrink-0 text-text-muted">
            {expanded ? (
              <ChevronUp className="h-4 w-4" />
            ) : (
              <ChevronDown className="h-4 w-4" />
            )}
          </div>
        )}
      </div>

      {expanded && totalStages > 0 && (
        <div className="border-t border-border px-3 pb-3 pt-2 space-y-1">
          {worker.stages.map((stage: StageExecution) => {
            const display = stageDisplayInfo.find((d) => d.stageName === stage.name);

            const stageStatusColor = {
              pending: "text-text-muted",
              running: "text-neon-orange",
              completed: "text-neon-green",
              failed: "text-danger",
              paused: "text-warning",
              stopped: "text-text-muted",
            }[stage.status];

            const StageIcon = {
              pending: Clock,
              running: Loader2,
              completed: CheckCircle2,
              failed: XCircle,
              paused: Clock,
              stopped: Clock,
            }[stage.status];

            return (
              <div
                key={stage.name}
                data-testid={`flow-monitor-stage-${stage.name}`}
                className="flex items-center gap-2 rounded-md bg-bg-tertiary px-3 py-1.5"
              >
                <StageIcon
                  className={`h-3.5 w-3.5 shrink-0 ${stageStatusColor} ${
                    stage.status === "running" ? "animate-spin" : ""
                  }`}
                />
                <span className="text-xs text-text-primary">
                  {display ? display.name : stage.name}
                </span>
                {display && (
                  <span className="text-xs text-text-muted">
                    {stripWstgPrefix(display.sectionId)}
                  </span>
                )}
                <span data-testid={`flow-monitor-status-${stage.name}`} className={`ml-auto text-xs font-semibold uppercase ${stageStatusColor}`}>
                  {stage.status}
                </span>
                {stage.tool && (
                  <span className="text-xs text-text-muted font-mono">{stage.tool}</span>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

export default function FlowPage() {
  const activeTarget = useCampaignStore((s) => s.activeTarget);
  const jobs = useCampaignStore((s) => s.jobs);

  const [playbooks, setPlaybooks] = useState<PlaybookRow[]>([]);
  const [playbooksLoading, setPlaybooksLoading] = useState(true);
  const [playbooksError, setPlaybooksError] = useState<string | null>(null);
  const [selectedPlaybook, setSelectedPlaybook] = useState<string>("");
  const [workers, setWorkers] = useState<WorkerConfig[]>([]);
  const [expandedWorkers, setExpandedWorkers] = useState<Set<string>>(new Set());

  const [execution, setExecution] = useState<ExecutionState | null>(null);
  const [pollError, setPollError] = useState(false);
  const [expandedMonitorWorkers, setExpandedMonitorWorkers] = useState<Set<string>>(new Set());

  useEffect(() => {
    let cancelled = false;

    api
      .getPlaybooks()
      .then((res) => {
        if (!cancelled) {
          setPlaybooks(res);
          setPlaybooksLoading(false);
        }
      })
      .catch((err) => {
        if (!cancelled) {
          setPlaybooksError(
            err instanceof Error ? err.message : "Failed to load playbooks",
          );
          setPlaybooksLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, []);

  const handlePlaybookChange = useCallback(
    (name: string) => {
      setSelectedPlaybook(name);
      if (!name) {
        setWorkers([]);
        return;
      }
      const pb = playbooks.find((p) => p.name === name);
      if (pb && pb.workers && pb.workers.length > 0) {
        setWorkers(pb.workers.map((w) => ({
          ...w,
          stages: w.stages.map((s) => ({ ...s })),
        })));
        setExpandedWorkers(new Set(pb.workers.map((w) => w.name)));
      } else {
        setWorkers([]);
        setExpandedWorkers(new Set());
      }
    },
    [playbooks],
  );

  const toggleWorker = useCallback((workerName: string) => {
    setWorkers((prev) => {
      const target = prev.find((w) => w.name === workerName);
      if (!target) return prev;

      const newEnabled = !target.enabled;
      let updated = prev.map((w) =>
        w.name === workerName ? { ...w, enabled: newEnabled } : w,
      );

      if (!newEnabled) {
        const downstream = getTransitiveDownstream(workerName);
        updated = updated.map((w) =>
          downstream.has(w.name) ? { ...w, enabled: false } : w,
        );
      }

      return updated;
    });
  }, []);

  const toggleStage = useCallback((workerName: string, stageIndex: number) => {
    setWorkers((prev) =>
      prev.map((w) =>
        w.name === workerName
          ? {
              ...w,
              stages: w.stages.map((s, i) =>
                i === stageIndex ? { ...s, enabled: !s.enabled } : s,
              ),
            }
          : w,
      ),
    );
  }, []);

  const updateStageTimeout = useCallback(
    (workerName: string, stageIndex: number, value: number) => {
      setWorkers((prev) =>
        prev.map((w) =>
          w.name === workerName
            ? {
                ...w,
                stages: w.stages.map((s, i) =>
                  i === stageIndex ? { ...s, tool_timeout: value } : s,
                ),
              }
            : w,
        ),
      );
    },
    [],
  );

  const toggleExpandWorker = useCallback((workerName: string) => {
    setExpandedWorkers((prev) => {
      const next = new Set(prev);
      if (next.has(workerName)) {
        next.delete(workerName);
      } else {
        next.add(workerName);
      }
      return next;
    });
  }, []);

  const toggleExpandMonitorWorker = useCallback((workerName: string) => {
    setExpandedMonitorWorkers((prev) => {
      const next = new Set(prev);
      if (next.has(workerName)) {
        next.delete(workerName);
      } else {
        next.add(workerName);
      }
      return next;
    });
  }, []);

  const handleSavePlaybook = useCallback(async () => {
    const name = `custom_${Date.now()}`;
    try {
      const result = await api.createPlaybook({
        name,
        description: `Custom playbook based on ${selectedPlaybook}`,
        workers,
      });
      setPlaybooks((prev) => [...prev, result]);
      setSelectedPlaybook(result.name);
    } catch {
      // toast shown by api.request()
    }
  }, [selectedPlaybook, workers]);

  const handleApply = useCallback(async () => {
    if (!activeTarget || !selectedPlaybook) return;
    try {
      await api.applyPlaybook(activeTarget.id, selectedPlaybook);
    } catch {
      // toast shown by api.request()
    }
  }, [activeTarget, selectedPlaybook]);

  useEffect(() => {
    if (!activeTarget) return;
    let cancelled = false;

    const fetchExecution = () => {
      api
        .getExecutionState(activeTarget.id)
        .then((res) => {
          if (!cancelled) {
            setExecution(res);
            setPollError(false);

            if (res?.workers) {
              setExpandedMonitorWorkers((prev) => {
                const next = new Set(prev);
                for (const w of res.workers) {
                  if (w.status === "failed") next.add(w.name);
                  if (w.status === "completed") next.delete(w.name);
                  if (w.status === "running" && !prev.has(w.name)) next.add(w.name);
                }
                return next;
              });
            }
          }
        })
        .catch(() => {
          if (!cancelled) {
            setPollError(true);
          }
        });
    };

    fetchExecution();
    const interval = setInterval(fetchExecution, 10_000);

    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [activeTarget]);

  const orderedConfigWorkers = useMemo(() => {
    const workerMap = new Map(workers.map((w) => [w.name, w]));
    return PIPELINE_WORKER_NAMES.map((name) => workerMap.get(name)).filter(
      (w): w is WorkerConfig => w !== undefined,
    );
  }, [workers]);

  const orderedExecWorkers = useMemo(() => {
    if (!execution?.workers) return [];
    const workerMap = new Map(execution.workers.map((w) => [w.name, w]));
    return PIPELINE_WORKER_NAMES.map((name) => workerMap.get(name)).filter(
      (w): w is WorkerExecution => w !== undefined,
    );
  }, [execution]);

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-bold text-text-primary">
            <Workflow className="h-5 w-5 text-neon-orange" />
            Phase Flow
          </h1>
          <p className="mt-1 text-sm text-text-secondary">
            Configure scan playbooks and monitor pipeline execution
          </p>
        </div>
        {activeTarget && (
          <span className="rounded-md bg-bg-secondary px-3 py-1.5 font-mono text-sm text-neon-orange">
            {activeTarget.base_domain}
          </span>
        )}
      </div>

      <div className="grid grid-cols-2 gap-6 animate-fade-in">
        <div className="space-y-4">
          <h2 className="text-lg font-semibold text-text-primary">
            Playbook Configurator
          </h2>

          {playbooksError ? (
            <div className="rounded-lg border border-danger/30 bg-danger/10 p-4 text-sm text-danger">
              <AlertTriangle className="mb-1 inline h-4 w-4" /> Failed to load
              playbooks: {playbooksError}
            </div>
          ) : (
            <select
              data-testid="flow-playbook-select"
              value={selectedPlaybook}
              onChange={(e) => handlePlaybookChange(e.target.value)}
              disabled={playbooksLoading}
              className="w-full rounded-md border border-border bg-bg-secondary px-3 py-2 font-mono text-sm text-text-primary input-focus"
            >
              <option value="">
                {playbooksLoading
                  ? "Loading playbooks..."
                  : "Select a playbook..."}
              </option>
              {playbooks.map((pb) => (
                <option key={pb.name} value={pb.name}>
                  {pb.name}
                  {pb.builtin ? " (built-in)" : ""}
                </option>
              ))}
            </select>
          )}

          {!selectedPlaybook && !playbooksError && (
            <div
              data-testid="flow-empty-config"
              className="flex flex-col items-center justify-center rounded-lg border border-dashed border-border-accent bg-bg-tertiary p-8 text-center"
            >
              <Play className="mb-3 h-8 w-8 text-text-muted" />
              <p className="text-sm text-text-muted">
                Select a playbook to configure your scan pipeline
              </p>
            </div>
          )}

          {selectedPlaybook && orderedConfigWorkers.length > 0 && (
            <div className="space-y-2">
              {orderedConfigWorkers.map((worker) => (
                <WorkerCard
                  key={worker.name}
                  worker={worker}
                  workers={workers}
                  expanded={expandedWorkers.has(worker.name)}
                  onToggleExpand={() => toggleExpandWorker(worker.name)}
                  onToggleWorker={() => toggleWorker(worker.name)}
                  onToggleStage={(idx) => toggleStage(worker.name, idx)}
                  onStageTimeoutChange={(idx, val) =>
                    updateStageTimeout(worker.name, idx, val)
                  }
                />
              ))}
            </div>
          )}

          {selectedPlaybook && (
            <div className="flex items-center gap-3 border-t border-border pt-4">
              <button
                data-testid="flow-save-playbook-btn"
                onClick={handleSavePlaybook}
                className="inline-flex items-center gap-2 rounded-md border border-border bg-bg-surface px-4 py-2 text-xs font-medium text-text-secondary transition-colors hover:border-neon-green/40 hover:text-neon-green"
              >
                <Save className="h-3.5 w-3.5" />
                Save as Custom Playbook
              </button>

              <div
                data-testid="flow-apply-target-select"
                className="flex items-center gap-2 text-xs text-text-muted"
              >
                Target:{" "}
                <span className="font-mono text-text-primary">
                  {activeTarget
                    ? activeTarget.base_domain
                    : "No target selected"}
                </span>
              </div>

              <button
                data-testid="flow-apply-btn"
                onClick={handleApply}
                disabled={!activeTarget}
                className="ml-auto inline-flex items-center gap-2 rounded-md bg-neon-orange px-4 py-2 text-xs font-semibold text-bg-primary transition-colors hover:bg-neon-orange-dim disabled:opacity-50"
              >
                <Play className="h-3.5 w-3.5" />
                Apply to Target
              </button>
            </div>
          )}
        </div>

        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-text-primary">
              Execution Monitor
            </h2>
            <div
              data-testid="flow-monitor-target-select"
              className="flex items-center gap-2 text-xs"
            >
              {activeTarget ? (
                <>
                  <span className="text-text-muted">Monitoring:</span>
                  <span className="font-mono text-neon-orange">
                    {activeTarget.base_domain}
                  </span>
                </>
              ) : (
                <span className="text-text-muted">No target</span>
              )}
            </div>
          </div>

          {pollError && (
            <div
              data-testid="flow-connection-lost"
              className="flex items-center gap-2 rounded-lg border border-warning/30 bg-warning/10 p-3 text-sm text-warning"
            >
              <AlertTriangle className="h-4 w-4 shrink-0" />
              <span>Connection lost — retrying...</span>
              <RefreshCw className="ml-auto h-4 w-4 animate-spin" />
            </div>
          )}

          {!activeTarget && (
            <div
              data-testid="flow-empty-monitor"
              className="flex flex-col items-center justify-center rounded-lg border border-dashed border-border-accent bg-bg-tertiary p-8 text-center"
            >
              <Eye className="mb-3 h-8 w-8 text-text-muted" />
              <p className="text-sm text-text-muted">
                Select a target to view execution progress
              </p>
            </div>
          )}

          {activeTarget && !execution && !pollError && (
            <div
              data-testid="flow-empty-monitor"
              className="flex flex-col items-center justify-center rounded-lg border border-dashed border-border-accent bg-bg-tertiary p-8 text-center"
            >
              <Eye className="mb-3 h-8 w-8 text-text-muted" />
              <p className="text-sm text-text-muted">
                No scans running. Apply a playbook to a target to begin.
              </p>
            </div>
          )}

          {execution && orderedExecWorkers.length > 0 && (
            <div className="space-y-2">
              <div className="flex items-center gap-2 rounded-md bg-bg-tertiary px-3 py-2 text-xs">
                <Workflow className="h-3.5 w-3.5 text-neon-orange" />
                <span className="text-text-muted">Playbook:</span>
                <span className="font-mono text-text-primary">
                  {execution.playbook}
                </span>
              </div>

              {orderedExecWorkers.map((worker) => (
                <MonitorWorkerCard
                  key={worker.name}
                  worker={worker}
                  expanded={expandedMonitorWorkers.has(worker.name)}
                  onToggleExpand={() => toggleExpandMonitorWorker(worker.name)}
                />
              ))}
            </div>
          )}
        </div>
      </div>

      {activeTarget && (
        <div className="rounded-lg border border-border bg-bg-secondary p-4">
          <ScanTimeline jobs={jobs} />
        </div>
      )}
    </div>
  );
}
