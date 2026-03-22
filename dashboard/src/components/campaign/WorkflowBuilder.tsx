"use client";

import { useState, useCallback, useMemo } from "react";
import {
  ChevronDown,
  ChevronRight,
  Save,
  Layers,
  Check,
} from "lucide-react";

/* ------------------------------------------------------------------ */
/* Hardcoded phase/tool structure                                     */
/* ------------------------------------------------------------------ */

export interface PhaseConfig {
  id: string;
  label: string;
  tools: string[];
}

const DEFAULT_PHASES: PhaseConfig[] = [
  {
    id: "phase_1",
    label: "Phase 1 — Passive Recon",
    tools: ["subfinder", "amass", "assetfinder", "crt.sh"],
  },
  {
    id: "phase_2",
    label: "Phase 2 — Active Recon",
    tools: ["nmap", "masscan", "naabu"],
  },
  {
    id: "phase_3",
    label: "Phase 3 — Content Discovery",
    tools: ["httpx", "katana", "gospider"],
  },
  {
    id: "phase_4",
    label: "Phase 4 — Cloud Enum",
    tools: ["cloud_enum", "s3scanner"],
  },
  {
    id: "phase_5",
    label: "Phase 5 — Vuln Scanning",
    tools: ["nuclei", "dalfox"],
  },
  {
    id: "phase_6",
    label: "Phase 6 — API Testing",
    tools: ["paramspider", "arjun"],
  },
];

/* ------------------------------------------------------------------ */
/* Types                                                              */
/* ------------------------------------------------------------------ */

export interface WorkflowState {
  /** phaseId -> set of enabled tool names */
  phases: Record<string, Set<string>>;
}

interface WorkflowBuilderProps {
  value: WorkflowState;
  onChange: (state: WorkflowState) => void;
}

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

function initWorkflowState(): WorkflowState {
  const phases: Record<string, Set<string>> = {};
  for (const p of DEFAULT_PHASES) {
    phases[p.id] = new Set(p.tools);
  }
  return { phases };
}

export { initWorkflowState, DEFAULT_PHASES };

/* ------------------------------------------------------------------ */
/* Component                                                          */
/* ------------------------------------------------------------------ */

export default function WorkflowBuilder({ value, onChange }: WorkflowBuilderProps) {
  const [expanded, setExpanded] = useState<Record<string, boolean>>(() => {
    const m: Record<string, boolean> = {};
    for (const p of DEFAULT_PHASES) m[p.id] = true;
    return m;
  });

  const [saveInputOpen, setSaveInputOpen] = useState(false);
  const [playbookName, setPlaybookName] = useState("");
  const [savedMsg, setSavedMsg] = useState("");

  /* ---- derived counts ---- */
  const { enabledPhases, totalPhases, activeTools, totalTools } = useMemo(() => {
    let ep = 0;
    let at = 0;
    let tt = 0;
    for (const p of DEFAULT_PHASES) {
      const set = value.phases[p.id];
      const count = set ? set.size : 0;
      tt += p.tools.length;
      at += count;
      if (count > 0) ep += 1;
    }
    return { enabledPhases: ep, totalPhases: DEFAULT_PHASES.length, activeTools: at, totalTools: tt };
  }, [value]);

  /* ---- toggle helpers ---- */
  const togglePhase = useCallback(
    (phaseId: string) => {
      const phase = DEFAULT_PHASES.find((p) => p.id === phaseId);
      if (!phase) return;
      const current = value.phases[phaseId];
      const allEnabled = current && current.size === phase.tools.length;
      const next = { ...value.phases };
      next[phaseId] = allEnabled ? new Set<string>() : new Set(phase.tools);
      onChange({ phases: next });
    },
    [value, onChange],
  );

  const toggleTool = useCallback(
    (phaseId: string, tool: string) => {
      const current = value.phases[phaseId] ?? new Set<string>();
      const next = new Set(current);
      if (next.has(tool)) {
        next.delete(tool);
      } else {
        next.add(tool);
      }
      onChange({ phases: { ...value.phases, [phaseId]: next } });
    },
    [value, onChange],
  );

  const toggleExpand = useCallback((phaseId: string) => {
    setExpanded((prev) => ({ ...prev, [phaseId]: !prev[phaseId] }));
  }, []);

  /* ---- save custom playbook to localStorage ---- */
  const handleSave = useCallback(() => {
    if (!playbookName.trim()) return;
    const serializable: Record<string, string[]> = {};
    for (const [k, v] of Object.entries(value.phases)) {
      serializable[k] = Array.from(v);
    }
    const stored = JSON.parse(localStorage.getItem("webbh-custom-playbooks") ?? "{}");
    stored[playbookName.trim()] = serializable;
    localStorage.setItem("webbh-custom-playbooks", JSON.stringify(stored));
    setSavedMsg(`Saved "${playbookName.trim()}"`);
    setPlaybookName("");
    setSaveInputOpen(false);
    setTimeout(() => setSavedMsg(""), 3000);
  }, [playbookName, value]);

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <Layers className="h-4 w-4 text-neon-blue" />
        <span className="text-sm font-medium text-text-primary">Workflow Builder</span>
      </div>

      <p className="text-xs text-text-muted">
        Enable or disable phases and individual tools. Unchecking a phase disables all its tools.
      </p>

      {/* Phase tree */}
      <div className="space-y-1">
        {DEFAULT_PHASES.map((phase) => {
          const enabledSet = value.phases[phase.id] ?? new Set<string>();
          const allChecked = enabledSet.size === phase.tools.length;
          const someChecked = enabledSet.size > 0 && !allChecked;
          const isExpanded = expanded[phase.id] ?? false;

          return (
            <div
              key={phase.id}
              className="rounded-md border border-border bg-bg-tertiary overflow-hidden"
            >
              {/* Phase header */}
              <div className="flex items-center gap-2 px-3 py-2">
                <button
                  type="button"
                  onClick={() => toggleExpand(phase.id)}
                  className="text-text-muted hover:text-text-secondary transition-colors"
                >
                  {isExpanded ? (
                    <ChevronDown className="h-3.5 w-3.5" />
                  ) : (
                    <ChevronRight className="h-3.5 w-3.5" />
                  )}
                </button>

                {/* Phase checkbox */}
                <button
                  type="button"
                  onClick={() => togglePhase(phase.id)}
                  className={`flex h-4 w-4 shrink-0 items-center justify-center rounded border transition-colors ${
                    allChecked
                      ? "border-neon-orange bg-neon-orange"
                      : someChecked
                        ? "border-neon-orange bg-neon-orange/30"
                        : "border-border-accent bg-bg-surface"
                  }`}
                >
                  {(allChecked || someChecked) && (
                    <Check className="h-2.5 w-2.5 text-bg-primary" />
                  )}
                </button>

                <button
                  type="button"
                  onClick={() => toggleExpand(phase.id)}
                  className="flex-1 text-left"
                >
                  <span className="text-xs font-semibold text-text-primary">
                    {phase.label}
                  </span>
                  <span className="ml-2 text-[10px] text-text-muted">
                    {enabledSet.size}/{phase.tools.length} tools
                  </span>
                </button>
              </div>

              {/* Tools list */}
              {isExpanded && (
                <div className="border-t border-border bg-bg-secondary px-3 py-2 space-y-1 animate-fade-in">
                  {phase.tools.map((tool) => {
                    const checked = enabledSet.has(tool);
                    return (
                      <label
                        key={tool}
                        className="flex items-center gap-2.5 cursor-pointer py-0.5 group"
                      >
                        <button
                          type="button"
                          onClick={() => toggleTool(phase.id, tool)}
                          className={`flex h-3.5 w-3.5 shrink-0 items-center justify-center rounded-sm border transition-colors ${
                            checked
                              ? "border-neon-green bg-neon-green"
                              : "border-border-accent bg-bg-surface group-hover:border-text-muted"
                          }`}
                        >
                          {checked && (
                            <Check className="h-2 w-2 text-bg-primary" />
                          )}
                        </button>
                        <span
                          className={`font-mono text-xs transition-colors ${
                            checked ? "text-text-primary" : "text-text-muted"
                          }`}
                        >
                          {tool}
                        </span>
                      </label>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Summary */}
      <div className="flex items-center justify-between rounded-md border border-border bg-bg-surface px-3 py-2">
        <span className="text-xs text-text-secondary">
          <span className="font-mono text-neon-green">{enabledPhases}</span> of{" "}
          <span className="font-mono">{totalPhases}</span> phases enabled,{" "}
          <span className="font-mono text-neon-blue">{activeTools}</span> of{" "}
          <span className="font-mono">{totalTools}</span> tools active
        </span>
      </div>

      {/* Save as custom playbook */}
      <div className="space-y-2">
        {!saveInputOpen ? (
          <button
            type="button"
            onClick={() => setSaveInputOpen(true)}
            className="flex items-center gap-1.5 text-xs text-text-muted hover:text-neon-orange transition-colors"
          >
            <Save className="h-3 w-3" />
            Save as custom playbook
          </button>
        ) : (
          <div className="flex items-center gap-2 animate-fade-in">
            <input
              type="text"
              value={playbookName}
              onChange={(e) => setPlaybookName(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleSave()}
              placeholder="Playbook name..."
              className="flex-1 rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 font-mono text-xs text-text-primary placeholder:text-text-muted input-focus"
              autoFocus
            />
            <button
              type="button"
              onClick={handleSave}
              disabled={!playbookName.trim()}
              className="rounded-md bg-neon-orange/15 px-3 py-1.5 text-xs font-medium text-neon-orange transition-colors hover:bg-neon-orange/25 disabled:opacity-40"
            >
              Save
            </button>
            <button
              type="button"
              onClick={() => {
                setSaveInputOpen(false);
                setPlaybookName("");
              }}
              className="text-xs text-text-muted hover:text-text-secondary transition-colors"
            >
              Cancel
            </button>
          </div>
        )}

        {savedMsg && (
          <p className="text-[10px] text-neon-green animate-fade-in">{savedMsg}</p>
        )}
      </div>
    </div>
  );
}
