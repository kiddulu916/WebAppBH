"use client";

import { useEffect, useState, useCallback } from "react";
import Link from "next/link";
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
} from "lucide-react";
import { useCampaignStore } from "@/stores/campaign";
import { api } from "@/lib/api";
import type { PlaybookRow, StageConfig } from "@/lib/api";
import type { ExecutionState, StageExecution } from "@/types/schema";

/* ------------------------------------------------------------------ */
/* Default recon stages (used when a playbook has no stages defined)    */
/* ------------------------------------------------------------------ */

const DEFAULT_STAGES: StageConfig[] = [
  { name: "passive_discovery", enabled: true, tool_timeout: 300 },
  { name: "active_discovery", enabled: true, tool_timeout: 300 },
  { name: "port_scanning", enabled: true, tool_timeout: 600 },
  { name: "service_detection", enabled: true, tool_timeout: 300 },
  { name: "web_crawling", enabled: true, tool_timeout: 300 },
  { name: "vulnerability_scanning", enabled: true, tool_timeout: 600 },
  { name: "exploitation", enabled: false, tool_timeout: 600 },
];

/* ------------------------------------------------------------------ */
/* Stage Card (Configurator)                                           */
/* ------------------------------------------------------------------ */

function StageCard({
  stage,
  onToggle,
  onTimeoutChange,
}: {
  stage: StageConfig;
  onToggle: () => void;
  onTimeoutChange: (v: number) => void;
}) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div
      data-testid={`flow-stage-card-${stage.name}`}
      className={`rounded-lg border border-border bg-bg-secondary p-4 transition-all ${
        !stage.enabled ? "opacity-50" : ""
      }`}
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          {/* Toggle switch */}
          <button
            type="button"
            data-testid={`flow-stage-toggle-${stage.name}`}
            onClick={onToggle}
            className={`relative h-5 w-9 shrink-0 rounded-full transition-colors ${
              stage.enabled ? "bg-neon-green" : "bg-border-accent"
            }`}
            aria-label={`Toggle ${stage.name}`}
          >
            <span
              className={`absolute top-0.5 left-0.5 h-4 w-4 rounded-full bg-white transition-transform ${
                stage.enabled ? "translate-x-4" : ""
              }`}
            />
          </button>

          <span className="font-mono text-sm text-text-primary">
            {stage.name}
          </span>
        </div>

        <button
          type="button"
          data-testid={`flow-stage-expand-${stage.name}`}
          onClick={() => setExpanded(!expanded)}
          className="rounded p-1 text-text-muted hover:bg-bg-tertiary hover:text-text-primary"
          aria-label={`Expand ${stage.name}`}
        >
          {expanded ? (
            <ChevronUp className="h-4 w-4" />
          ) : (
            <ChevronDown className="h-4 w-4" />
          )}
        </button>
      </div>

      {/* Expanded: tool timeout parameter */}
      {expanded && (
        <div className="mt-3 border-t border-border pt-3">
          <div className="flex items-center gap-3">
            <label className="text-xs text-text-muted">Tool Timeout:</label>
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
        </div>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Monitor Stage Entry                                                 */
/* ------------------------------------------------------------------ */

function MonitorStageEntry({ stage }: { stage: StageExecution }) {
  const statusColor =
    stage.status === "running"
      ? "text-neon-orange"
      : stage.status === "completed"
        ? "text-neon-green"
        : stage.status === "failed"
          ? "text-danger"
          : "text-text-muted";

  const StatusIcon =
    stage.status === "completed"
      ? CheckCircle2
      : stage.status === "failed"
        ? XCircle
        : stage.status === "running"
          ? Loader2
          : Clock;

  return (
    <div
      data-testid={`flow-monitor-stage-${stage.name}`}
      className={`flex items-center gap-4 rounded-lg border border-border bg-bg-secondary p-3 transition-all ${
        stage.status === "running" ? "animate-pulse-orange" : ""
      }`}
    >
      {/* Timeline dot / icon */}
      <div className={`shrink-0 ${statusColor}`}>
        <StatusIcon
          className={`h-5 w-5 ${stage.status === "running" ? "animate-spin" : ""}`}
        />
      </div>

      {/* Stage info */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="font-mono text-sm text-text-primary">
            {stage.name}
          </span>
          <span
            data-testid={`flow-monitor-status-${stage.name}`}
            className={`text-xs font-semibold uppercase ${statusColor}`}
          >
            {stage.status}
          </span>
        </div>
        {stage.tool && (
          <span
            data-testid={`flow-monitor-tool-${stage.name}`}
            className="text-xs text-text-muted"
          >
            Running: <span className="font-mono text-neon-orange">{stage.tool}</span>
          </span>
        )}
        {!stage.tool && (
          <span
            data-testid={`flow-monitor-tool-${stage.name}`}
            className="text-xs text-text-muted"
          >
            {stage.status === "completed"
              ? "All tools finished"
              : stage.status === "failed"
                ? "Stage failed"
                : "Waiting..."}
          </span>
        )}
      </div>

      {/* View logs link */}
      <Link
        href="/campaign/c2"
        data-testid={`flow-monitor-logs-link-${stage.name}`}
        className="shrink-0 text-xs text-neon-blue hover:underline"
      >
        View Logs
      </Link>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Main page                                                           */
/* ------------------------------------------------------------------ */

export default function FlowPage() {
  const activeTarget = useCampaignStore((s) => s.activeTarget);

  /* ---- Configurator state ---- */
  const [playbooks, setPlaybooks] = useState<PlaybookRow[]>([]);
  const [playbooksLoading, setPlaybooksLoading] = useState(true);
  const [playbooksError, setPlaybooksError] = useState<string | null>(null);
  const [selectedPlaybook, setSelectedPlaybook] = useState<string>("");
  const [stages, setStages] = useState<StageConfig[]>([]);

  /* ---- Monitor state ---- */
  const [execution, setExecution] = useState<ExecutionState | null>(null);
  const [pollError, setPollError] = useState(false);

  /* ---- Fetch playbooks on mount ---- */
  useEffect(() => {
    let cancelled = false;
    setPlaybooksLoading(true);
    setPlaybooksError(null);

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

  /* ---- Handle playbook selection ---- */
  const handlePlaybookChange = useCallback(
    (name: string) => {
      setSelectedPlaybook(name);
      if (!name) {
        setStages([]);
        return;
      }
      const pb = playbooks.find((p) => p.name === name);
      if (pb && pb.stages && pb.stages.length > 0) {
        setStages(pb.stages.map((s) => ({ ...s })));
      } else {
        setStages(DEFAULT_STAGES.map((s) => ({ ...s })));
      }
    },
    [playbooks],
  );

  /* ---- Stage toggle ---- */
  const toggleStage = useCallback((index: number) => {
    setStages((prev) =>
      prev.map((s, i) => (i === index ? { ...s, enabled: !s.enabled } : s)),
    );
  }, []);

  /* ---- Stage timeout change ---- */
  const updateTimeout = useCallback((index: number, value: number) => {
    setStages((prev) =>
      prev.map((s, i) => (i === index ? { ...s, tool_timeout: value } : s)),
    );
  }, []);

  /* ---- Save as custom playbook ---- */
  const handleSavePlaybook = useCallback(async () => {
    const name = `custom_${Date.now()}`;
    try {
      const result = await api.createPlaybook({
        name,
        description: `Custom playbook based on ${selectedPlaybook}`,
        stages,
      });
      setPlaybooks((prev) => [...prev, result]);
      setSelectedPlaybook(result.name);
    } catch {
      // toast shown by api.request()
    }
  }, [selectedPlaybook, stages]);

  /* ---- Apply playbook to target ---- */
  const handleApply = useCallback(async () => {
    if (!activeTarget || !selectedPlaybook) return;
    try {
      await api.applyPlaybook(activeTarget.id, selectedPlaybook);
    } catch {
      // toast shown by api.request()
    }
  }, [activeTarget, selectedPlaybook]);

  /* ---- Poll execution state ---- */
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

  /* ---------------------------------------------------------------- */
  /* Render                                                            */
  /* ---------------------------------------------------------------- */

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
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

      {/* Two-panel split */}
      <div className="grid grid-cols-2 gap-6 animate-fade-in">
        {/* ============================================================ */}
        {/* Left: Playbook Configurator                                   */}
        {/* ============================================================ */}
        <div className="space-y-4">
          <h2 className="text-lg font-semibold text-text-primary">
            Playbook Configurator
          </h2>

          {/* Playbook select dropdown */}
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

          {/* Empty state: no playbook selected */}
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

          {/* Stage cards */}
          {selectedPlaybook && stages.length > 0 && (
            <div className="space-y-2">
              {stages.map((stage, i) => (
                <StageCard
                  key={stage.name}
                  stage={stage}
                  onToggle={() => toggleStage(i)}
                  onTimeoutChange={(v) => updateTimeout(i, v)}
                />
              ))}
            </div>
          )}

          {/* Action buttons */}
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

              {/* Target selector for apply */}
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

        {/* ============================================================ */}
        {/* Right: Live Execution Monitor                                 */}
        {/* ============================================================ */}
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

          {/* Connection lost banner */}
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

          {/* Empty monitor state */}
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

          {/* Execution stage timeline */}
          {execution && execution.stages && execution.stages.length > 0 && (
            <div className="space-y-2">
              {/* Playbook label */}
              <div className="flex items-center gap-2 rounded-md bg-bg-tertiary px-3 py-2 text-xs">
                <Workflow className="h-3.5 w-3.5 text-neon-orange" />
                <span className="text-text-muted">Playbook:</span>
                <span className="font-mono text-text-primary">
                  {execution.playbook}
                </span>
              </div>

              {/* Stage entries */}
              {execution.stages.map((stage) => (
                <MonitorStageEntry key={stage.name} stage={stage} />
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
