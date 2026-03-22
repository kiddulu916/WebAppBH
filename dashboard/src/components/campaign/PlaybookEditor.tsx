"use client";

import { useState } from "react";
import { X, Save } from "lucide-react";
import type { StageConfig } from "@/lib/api";

const DEFAULT_STAGES: StageConfig[] = [
  { name: "passive_discovery", enabled: true, tool_timeout: 300 },
  { name: "active_discovery", enabled: true, tool_timeout: 300 },
  { name: "port_scanning", enabled: true, tool_timeout: 600 },
  { name: "service_detection", enabled: true, tool_timeout: 300 },
  { name: "web_crawling", enabled: true, tool_timeout: 300 },
  { name: "vulnerability_scanning", enabled: true, tool_timeout: 600 },
  { name: "exploitation", enabled: false, tool_timeout: 600 },
];

interface PlaybookEditorProps {
  onSave: (playbook: {
    name: string;
    description: string;
    stages: StageConfig[];
    concurrency: { heavy: number; light: number };
  }) => void;
  onCancel: () => void;
  initial?: {
    name: string;
    description: string;
    stages: StageConfig[];
    concurrency: { heavy: number; light: number };
  };
}

export default function PlaybookEditor({
  onSave,
  onCancel,
  initial,
}: PlaybookEditorProps) {
  const [name, setName] = useState(initial?.name ?? "");
  const [description, setDescription] = useState(initial?.description ?? "");
  const [stages, setStages] = useState<StageConfig[]>(
    initial?.stages ?? DEFAULT_STAGES,
  );
  const [heavy, setHeavy] = useState(initial?.concurrency?.heavy ?? 2);
  const [light, setLight] = useState(initial?.concurrency?.light ?? 4);

  const toggleStage = (index: number) => {
    setStages((prev) =>
      prev.map((s, i) =>
        i === index ? { ...s, enabled: !s.enabled } : s,
      ),
    );
  };

  const updateTimeout = (index: number, value: number) => {
    setStages((prev) =>
      prev.map((s, i) =>
        i === index ? { ...s, tool_timeout: value } : s,
      ),
    );
  };

  const handleSave = () => {
    if (!name.trim()) return;
    onSave({
      name: name.trim(),
      description: description.trim(),
      stages,
      concurrency: { heavy, light },
    });
  };

  return (
    <div className="space-y-4 rounded-lg border border-neon-orange/20 bg-bg-tertiary p-4 animate-fade-in">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-text-primary">
          {initial ? "Edit Playbook" : "Create Custom Playbook"}
        </h3>
        <button
          onClick={onCancel}
          className="text-text-muted hover:text-text-primary"
        >
          <X className="h-4 w-4" />
        </button>
      </div>

      {/* Name & Description */}
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

      {/* Stages */}
      <div>
        <span className="section-label mb-2 block">Stages</span>
        <div className="space-y-1.5">
          {stages.map((stage, i) => (
            <div
              key={stage.name}
              className={`flex items-center gap-3 rounded-md border px-3 py-2 transition-colors ${
                stage.enabled
                  ? "border-neon-green/20 bg-neon-green/5"
                  : "border-border bg-bg-void opacity-60"
              }`}
            >
              {/* Toggle */}
              <button
                type="button"
                onClick={() => toggleStage(i)}
                className={`relative h-4 w-8 shrink-0 rounded-full transition-colors ${
                  stage.enabled ? "bg-neon-green" : "bg-border-accent"
                }`}
              >
                <span
                  className={`absolute top-0.5 left-0.5 h-3 w-3 rounded-full bg-white transition-transform ${
                    stage.enabled ? "translate-x-4" : ""
                  }`}
                />
              </button>

              {/* Name */}
              <span className="flex-1 font-mono text-xs text-text-primary">
                {stage.name}
              </span>

              {/* Timeout slider */}
              {stage.enabled && (
                <div className="flex items-center gap-2">
                  <span className="text-[10px] text-text-muted">timeout:</span>
                  <input
                    type="range"
                    min={60}
                    max={1200}
                    step={60}
                    value={stage.tool_timeout ?? 300}
                    onChange={(e) => updateTimeout(i, Number(e.target.value))}
                    className="w-20 accent-neon-orange"
                  />
                  <span className="w-8 text-right font-mono text-[10px] text-text-muted">
                    {stage.tool_timeout ?? 300}s
                  </span>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Concurrency */}
      <div>
        <span className="section-label mb-2 block">Concurrency</span>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="text-[10px] text-text-muted">Heavy tasks</label>
            <div className="flex items-center gap-2 mt-1">
              <input
                type="range"
                min={1}
                max={8}
                value={heavy}
                onChange={(e) => setHeavy(Number(e.target.value))}
                className="flex-1 accent-neon-orange"
              />
              <span className="w-4 text-center font-mono text-xs text-text-primary">
                {heavy}
              </span>
            </div>
          </div>
          <div>
            <label className="text-[10px] text-text-muted">Light tasks</label>
            <div className="flex items-center gap-2 mt-1">
              <input
                type="range"
                min={1}
                max={16}
                value={light}
                onChange={(e) => setLight(Number(e.target.value))}
                className="flex-1 accent-neon-blue"
              />
              <span className="w-4 text-center font-mono text-xs text-text-primary">
                {light}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Actions */}
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
