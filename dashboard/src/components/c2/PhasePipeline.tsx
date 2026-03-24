"use client";

import { Check } from "lucide-react";
import type { JobState } from "@/types/schema";

/**
 * High-level campaign phases derived from worker types.
 * Order reflects the typical scan progression.
 */
const PHASES = [
  "recon",
  "cloud_testing",
  "network",
  "fuzzing",
  "webapp_testing",
  "api_testing",
  "vuln_scanner",
  "chain",
  "mobile",
  "reporting",
] as const;

const PHASE_LABELS: Record<string, string> = {
  recon: "Recon",
  cloud_testing: "Cloud Enum",
  network: "Network",
  fuzzing: "Fuzzing",
  webapp_testing: "Webapp",
  api_testing: "API Test",
  vuln_scanner: "Vuln Scan",
  chain: "Chain",
  mobile: "Mobile",
  reporting: "Reporting",
};

/** Extract the worker type from a container name like "webbh-recon-t1" */
function workerType(containerName: string): string {
  return containerName.replace("webbh-", "").replace(/-t\d+$/, "");
}

interface PhasePipelineProps {
  jobs: JobState[];
}

export default function PhasePipeline({ jobs }: PhasePipelineProps) {
  const activeSet = new Set<string>();
  const completedSet = new Set<string>();

  for (const job of jobs) {
    const wt = workerType(job.container_name);
    if (job.status === "RUNNING" || job.status === "QUEUED" || job.status === "PAUSED") {
      activeSet.add(wt);
    } else if (job.status === "COMPLETED") {
      completedSet.add(wt);
    }
  }

  // A phase that is both active and completed (e.g. re-run) should show as active
  for (const wt of activeSet) {
    completedSet.delete(wt);
  }

  return (
    <div className="rounded-lg border border-border bg-bg-secondary p-4">
      <div className="section-label mb-3">PHASE PIPELINE</div>
      <div className="flex items-start gap-1 overflow-x-auto pb-1">
        {PHASES.map((phase, i) => {
          const isCompleted = completedSet.has(phase);
          const isActive = activeSet.has(phase);
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
