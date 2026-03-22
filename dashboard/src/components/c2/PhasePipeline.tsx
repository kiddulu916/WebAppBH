"use client";

import { Check } from "lucide-react";

const PHASES = [
  "PASSIVE_RECON",
  "ACTIVE_RECON",
  "CONTENT_DISCOVERY",
  "CLOUD_ENUM",
  "VULN_SCAN",
  "API_TESTING",
  "PARAM_MINING",
  "FUZZING",
  "EXPLOIT",
  "REPORTING",
  "CLEANUP",
  "COMPLETE",
] as const;

const PHASE_LABELS: Record<string, string> = {
  PASSIVE_RECON: "Passive Recon",
  ACTIVE_RECON: "Active Recon",
  CONTENT_DISCOVERY: "Content Disc.",
  CLOUD_ENUM: "Cloud Enum",
  VULN_SCAN: "Vuln Scan",
  API_TESTING: "API Test",
  PARAM_MINING: "Param Mine",
  FUZZING: "Fuzzing",
  EXPLOIT: "Exploit",
  REPORTING: "Reporting",
  CLEANUP: "Cleanup",
  COMPLETE: "Complete",
};

interface PhasePipelineProps {
  currentPhase: string | null;
  completedPhases?: string[];
}

export default function PhasePipeline({
  currentPhase,
  completedPhases = [],
}: PhasePipelineProps) {
  const completedSet = new Set(completedPhases.map((p) => p.toUpperCase()));
  const currentNorm = currentPhase?.toUpperCase() ?? null;

  return (
    <div className="rounded-lg border border-border bg-bg-secondary p-4">
      <div className="section-label mb-3">PHASE PIPELINE</div>
      <div className="flex items-start gap-1 overflow-x-auto pb-1">
        {PHASES.map((phase, i) => {
          const isCompleted = completedSet.has(phase);
          const isActive = currentNorm === phase;
          const isPending = !isCompleted && !isActive;

          return (
            <div key={phase} className="flex items-start">
              {i > 0 && (
                <div className="mt-3 flex items-center">
                  <div
                    className={`h-px w-3 shrink-0 ${
                      isCompleted || isActive
                        ? "bg-neon-green/50"
                        : "bg-border"
                    }`}
                  />
                </div>
              )}
              <div className="flex flex-col items-center gap-1.5">
                <div
                  className={`flex h-6 items-center gap-1 rounded-full px-2.5 text-[10px] font-semibold uppercase tracking-wide transition-all ${
                    isCompleted
                      ? "border border-neon-green/30 bg-neon-green-glow text-neon-green glow-green"
                      : isActive
                        ? "border border-neon-orange/30 bg-neon-orange-glow text-neon-orange animate-pulse-orange"
                        : "border border-border bg-bg-tertiary text-text-muted"
                  }`}
                >
                  {isCompleted && <Check className="h-3 w-3" />}
                  {isActive && (
                    <span className="relative flex h-1.5 w-1.5">
                      <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-neon-orange opacity-75" />
                      <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-neon-orange" />
                    </span>
                  )}
                  <span className="font-mono">{i + 1}</span>
                </div>
                <span
                  className={`max-w-16 text-center text-[9px] leading-tight ${
                    isCompleted
                      ? "text-neon-green/70"
                      : isActive
                        ? "text-neon-orange/80"
                        : "text-text-muted/60"
                  } ${isPending ? "opacity-50" : ""}`}
                >
                  {PHASE_LABELS[phase]}
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
