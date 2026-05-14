"use client";

import { useState } from "react";
import { X, Save, ChevronDown, ChevronUp } from "lucide-react";
import type { WorkerConfig } from "@/lib/api";
import { WORKER_STAGES } from "@/lib/worker-stages";
import { PIPELINE_WORKER_NAMES } from "@/types/schema";

const INTENSITY_COPY = {
  low: "Conservative probes that look like normal client variation. Safe against most production targets.",
  medium: "⚠️ Adds active WAF probing and uncommon HTTP methods (PROPFIND, TRACE, HTTP/0.9). May appear in IDS/WAF logs as suspicious. Use when target authorization clearly covers active reconnaissance.",
  high: "⚠️⚠️ Sends malformed methods, garbage verbs, and aggressive plugin checks. Will trigger WAFs, may be blocked, and is conspicuous to defenders. Only use against authorized targets with explicit go-ahead for noisy fingerprinting.",
} as const;

function buildDefaultWorkers(): WorkerConfig[] {
  return PIPELINE_WORKER_NAMES.map((name) => ({
    name,
    enabled: true,
    stages: (WORKER_STAGES[name] || []).map((s) => ({
      name: s.stageName,
      enabled: true,
      tool_timeout: 600,
    })),
    concurrency: { heavy: 2, light: 4 },
  }));
}

interface PlaybookEditorProps {
  onSave: (playbook: {
    name: string;
    description: string;
    workers: WorkerConfig[];
  }) => void;
  onCancel: () => void;
}

export default function PlaybookEditor({
  onSave,
  onCancel,
}: PlaybookEditorProps) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [workers, setWorkers] = useState<WorkerConfig[]>(buildDefaultWorkers);
  const [expandedWorker, setExpandedWorker] = useState<string | null>(null);

  const toggleWorker = (workerName: string) => {
    setWorkers((prev) =>
      prev.map((w) =>
        w.name === workerName ? { ...w, enabled: !w.enabled } : w,
      ),
    );
  };

  const toggleStage = (workerName: string, stageIndex: number) => {
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
  };

  const updateStageConfig = (
    workerName: string,
    stageName: string,
    config: Record<string, unknown>,
  ) => {
    setWorkers((prev) =>
      prev.map((w) =>
        w.name === workerName
          ? {
              ...w,
              stages: w.stages.map((s) =>
                s.name === stageName
                  ? { ...s, config: { ...(s.config ?? {}), ...config } }
                  : s,
              ),
            }
          : w,
      ),
    );
  };

  const handleSave = () => {
    if (!name.trim()) return;
    onSave({
      name: name.trim(),
      description: description.trim(),
      workers,
    });
  };

  const formatWorkerName = (n: string) =>
    n.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());

  return (
    <div className="space-y-4 rounded-lg border border-neon-orange/20 bg-bg-tertiary p-4 animate-fade-in">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-text-primary">
          Create Custom Playbook
        </h3>
        <button
          onClick={onCancel}
          className="text-text-muted hover:text-text-primary"
        >
          <X className="h-4 w-4" />
        </button>
      </div>

      <div className="space-y-3">
        <div>
          <label className="section-label mb-1 block">Name</label>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="my_custom_playbook"
            className="w-full rounded-md border border-border bg-bg-void px-3 py-2 font-mono text-sm text-text-primary placeholder:text-text-muted input-focus"
          />
        </div>
        <div>
          <label className="section-label mb-1 block">Description</label>
          <input
            type="text"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="What this playbook focuses on..."
            className="w-full rounded-md border border-border bg-bg-void px-3 py-2 text-sm text-text-primary placeholder:text-text-muted input-focus"
          />
        </div>
      </div>

      <div>
        <span className="section-label mb-2 block">Workers</span>
        <div className="space-y-1.5 max-h-64 overflow-y-auto">
          {workers.map((worker) => {
            const enabledCount = worker.stages.filter((s) => s.enabled).length;
            const isExpanded = expandedWorker === worker.name;

            return (
              <div
                key={worker.name}
                className={`rounded-md border px-3 py-2 transition-colors ${
                  worker.enabled
                    ? "border-neon-green/20 bg-neon-green/5"
                    : "border-border bg-bg-void opacity-60"
                }`}
              >
                <div className="flex items-center gap-3">
                  <button
                    type="button"
                    onClick={() => toggleWorker(worker.name)}
                    className={`relative h-4 w-8 shrink-0 rounded-full transition-colors ${
                      worker.enabled ? "bg-neon-green" : "bg-border-accent"
                    }`}
                  >
                    <span
                      className={`absolute top-0.5 left-0.5 h-3 w-3 rounded-full bg-white transition-transform ${
                        worker.enabled ? "translate-x-4" : ""
                      }`}
                    />
                  </button>

                  <span className="flex-1 font-mono text-xs text-text-primary">
                    {formatWorkerName(worker.name)}
                  </span>

                  {worker.stages.length > 0 && (
                    <>
                      <span className="text-[10px] text-text-muted font-mono">
                        {enabledCount}/{worker.stages.length}
                      </span>
                      <button
                        type="button"
                        data-testid={`worker-expand-${worker.name}`}
                        onClick={() =>
                          setExpandedWorker(isExpanded ? null : worker.name)
                        }
                        className="text-text-muted hover:text-text-primary"
                      >
                        {isExpanded ? (
                          <ChevronUp className="h-3 w-3" />
                        ) : (
                          <ChevronDown className="h-3 w-3" />
                        )}
                      </button>
                    </>
                  )}
                </div>

                {isExpanded && (
                  <div className="mt-2 space-y-1 pl-11">
                    {worker.stages.map((stage, idx) => (
                      <div key={stage.name} className="space-y-1">
                        <div className="flex items-center gap-2">
                          <button
                            type="button"
                            onClick={() => toggleStage(worker.name, idx)}
                            disabled={!worker.enabled}
                            className={`relative h-3 w-6 shrink-0 rounded-full transition-colors ${
                              stage.enabled && worker.enabled
                                ? "bg-neon-green"
                                : "bg-border-accent"
                            }`}
                          >
                            <span
                              className={`absolute top-0.5 left-0.5 h-2 w-2 rounded-full bg-white transition-transform ${
                                stage.enabled && worker.enabled
                                  ? "translate-x-3"
                                  : ""
                              }`}
                            />
                          </button>
                          <span className="text-[10px] text-text-primary">
                            {stage.name}
                          </span>
                        </div>

                        {worker.name === "info_gathering" &&
                          stage.name === "web_server_fingerprint" && (
                            <fieldset
                              className="ml-8 mt-1"
                              data-testid="fp-intensity-selector"
                            >
                              <legend className="sr-only">
                                Fingerprint intensity
                              </legend>
                              {(
                                ["low", "medium", "high"] as const
                              ).map((level) => {
                                const selected =
                                  ((stage.config?.fingerprint_intensity as string) ??
                                    "low") === level;
                                return (
                                  <label
                                    key={level}
                                    className="flex items-start gap-2 py-0.5 cursor-pointer"
                                  >
                                    <input
                                      type="radio"
                                      name={`fp-intensity-${worker.name}-${stage.name}`}
                                      value={level}
                                      checked={selected}
                                      onChange={() =>
                                        updateStageConfig(
                                          worker.name,
                                          stage.name,
                                          { fingerprint_intensity: level },
                                        )
                                      }
                                      className="mt-0.5 accent-neon-orange"
                                      aria-describedby={`fp-${level}-help`}
                                    />
                                    <span>
                                      <span className="text-[10px] capitalize text-text-primary">
                                        {level}
                                      </span>
                                      {selected && (
                                        <span
                                          id={`fp-${level}-help`}
                                          role="note"
                                          className="block text-[9px] leading-tight text-text-muted mt-0.5"
                                        >
                                          {INTENSITY_COPY[level]}
                                        </span>
                                      )}
                                    </span>
                                  </label>
                                );
                              })}
                            </fieldset>
                          )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      <div className="flex justify-end gap-2 border-t border-border pt-3">
        <button
          onClick={onCancel}
          className="rounded-md px-3 py-1.5 text-xs text-text-muted hover:text-text-primary"
        >
          Cancel
        </button>
        <button
          onClick={handleSave}
          disabled={!name.trim()}
          className="flex items-center gap-1.5 rounded-md bg-neon-orange px-3 py-1.5 text-xs font-semibold text-bg-primary hover:bg-neon-orange-dim disabled:opacity-50"
        >
          <Save className="h-3 w-3" />
          Save Playbook
        </button>
      </div>
    </div>
  );
}
