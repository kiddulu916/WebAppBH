"use client";

import { useEffect, useState, useMemo } from "react";
import Link from "next/link";
import {
  Radar,
  Wifi,
  FolderSearch,
  Cloud,
  ShieldAlert,
  Code,
  Pickaxe,
  Zap,
  Bug,
  FileText,
  Trash2,
  CheckCircle2,
  Loader2,
  Eye,
  SkipForward,
  Pause,
  Database,
} from "lucide-react";
import { useCampaignStore } from "@/stores/campaign";
import { api } from "@/lib/api";
import type { JobState } from "@/types/schema";

/* ------------------------------------------------------------------ */
/* Phase definitions                                                   */
/* ------------------------------------------------------------------ */

interface PhaseDef {
  id: number;
  name: string;
  tools: string[];
  icon: React.ComponentType<{ className?: string }>;
  /** Keywords to match against job current_phase / container_name */
  matchKeys: string[];
}

const PHASES: PhaseDef[] = [
  {
    id: 1,
    name: "Passive Recon",
    tools: ["subfinder", "amass", "assetfinder", "crt.sh"],
    icon: Radar,
    matchKeys: ["passive", "recon_passive", "phase_1", "phase1"],
  },
  {
    id: 2,
    name: "Active Recon",
    tools: ["nmap", "masscan", "naabu"],
    icon: Wifi,
    matchKeys: ["active", "recon_active", "phase_2", "phase2"],
  },
  {
    id: 3,
    name: "Content Discovery",
    tools: ["httpx", "katana", "gospider"],
    icon: FolderSearch,
    matchKeys: ["content", "discovery", "phase_3", "phase3"],
  },
  {
    id: 4,
    name: "Cloud Enum",
    tools: ["cloud_enum", "s3scanner"],
    icon: Cloud,
    matchKeys: ["cloud", "phase_4", "phase4"],
  },
  {
    id: 5,
    name: "Vuln Scanning",
    tools: ["nuclei", "dalfox"],
    icon: ShieldAlert,
    matchKeys: ["vuln", "scanning", "phase_5", "phase5"],
  },
  {
    id: 6,
    name: "API Testing",
    tools: ["paramspider", "arjun"],
    icon: Code,
    matchKeys: ["api", "testing", "phase_6", "phase6"],
  },
  {
    id: 7,
    name: "Parameter Mining",
    tools: [],
    icon: Pickaxe,
    matchKeys: ["param", "mining", "phase_7", "phase7"],
  },
  {
    id: 8,
    name: "Fuzzing",
    tools: [],
    icon: Zap,
    matchKeys: ["fuzz", "phase_8", "phase8"],
  },
  {
    id: 9,
    name: "Exploit Verification",
    tools: [],
    icon: Bug,
    matchKeys: ["exploit", "verif", "phase_9", "phase9"],
  },
  {
    id: 10,
    name: "Reporting",
    tools: [],
    icon: FileText,
    matchKeys: ["report", "phase_10", "phase10"],
  },
  {
    id: 11,
    name: "Cleanup",
    tools: [],
    icon: Trash2,
    matchKeys: ["cleanup", "phase_11", "phase11"],
  },
  {
    id: 12,
    name: "Complete",
    tools: [],
    icon: CheckCircle2,
    matchKeys: ["complete", "done", "phase_12", "phase12"],
  },
];

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

type PhaseStatus = "completed" | "active" | "pending";

interface PhaseState {
  status: PhaseStatus;
  assetCount: number;
  toolCount: number;
  duration: string | null;
}

function matchPhase(job: JobState): number | null {
  const haystack = [
    job.current_phase ?? "",
    job.container_name,
    job.last_tool_executed ?? "",
  ]
    .join(" ")
    .toLowerCase();

  for (const phase of PHASES) {
    if (phase.matchKeys.some((k) => haystack.includes(k))) {
      return phase.id;
    }
  }
  return null;
}

function derivePhaseStates(jobs: JobState[]): Record<number, PhaseState> {
  const states: Record<number, PhaseState> = {};

  // Initialize all phases as pending
  for (const p of PHASES) {
    states[p.id] = {
      status: "pending",
      assetCount: 0,
      toolCount: p.tools.length,
      duration: null,
    };
  }

  // Determine which phase each job belongs to
  let highestCompleted = 0;
  let activePhaseId: number | null = null;

  for (const job of jobs) {
    const phaseId = matchPhase(job);
    if (!phaseId) continue;

    if (job.status === "COMPLETED") {
      if (phaseId > highestCompleted) highestCompleted = phaseId;
      states[phaseId].status = "completed";
      // Approximate duration from timestamps
      if (job.created_at && job.last_seen) {
        const start = new Date(job.created_at).getTime();
        const end = new Date(job.last_seen).getTime();
        const diffMs = end - start;
        if (diffMs > 0) {
          const mins = Math.floor(diffMs / 60000);
          const secs = Math.floor((diffMs % 60000) / 1000);
          states[phaseId].duration =
            mins > 0 ? `${mins}m ${secs}s` : `${secs}s`;
        }
      }
    } else if (job.status === "RUNNING") {
      states[phaseId].status = "active";
      activePhaseId = phaseId;
    }
  }

  // Mark all phases before the highest completed as completed
  for (let i = 1; i <= highestCompleted; i++) {
    if (states[i].status === "pending") {
      states[i].status = "completed";
    }
  }

  // If there is an active phase, mark everything before it as completed
  if (activePhaseId) {
    for (let i = 1; i < activePhaseId; i++) {
      if (states[i].status === "pending") {
        states[i].status = "completed";
      }
    }
  }

  return states;
}

/* ------------------------------------------------------------------ */
/* Phase Card                                                          */
/* ------------------------------------------------------------------ */

function PhaseCard({
  phase,
  state,
}: {
  phase: PhaseDef;
  state: PhaseState;
}) {
  const Icon = phase.icon;

  const borderClass =
    state.status === "completed"
      ? "border-l-neon-green border-l-2 border-t border-r border-b border-border glow-green"
      : state.status === "active"
        ? "border-l-neon-orange border-l-2 border-t border-r border-b border-border animate-pulse-orange"
        : "border border-dashed border-border-accent opacity-50";

  const bgClass =
    state.status === "completed"
      ? "bg-bg-secondary"
      : state.status === "active"
        ? "bg-bg-secondary"
        : "bg-bg-tertiary";

  return (
    <div
      className={`rounded-lg p-4 transition-all ${borderClass} ${bgClass} animate-fade-in`}
    >
      {/* Header */}
      <div className="mb-3 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Icon
            className={`h-4 w-4 ${
              state.status === "completed"
                ? "text-neon-green"
                : state.status === "active"
                  ? "text-neon-orange"
                  : "text-text-muted"
            }`}
          />
          <span className="section-label">Phase {phase.id}</span>
        </div>
        <StatusBadge status={state.status} />
      </div>

      {/* Name */}
      <h3
        className={`text-sm font-semibold ${
          state.status === "pending" ? "text-text-muted" : "text-text-primary"
        }`}
      >
        {phase.name}
      </h3>

      {/* Tools list */}
      {phase.tools.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1">
          {phase.tools.map((tool) => (
            <span
              key={tool}
              className="rounded bg-bg-surface px-1.5 py-0.5 font-mono text-[10px] text-text-muted"
            >
              {tool}
            </span>
          ))}
        </div>
      )}

      {/* Stats row */}
      <div className="mt-3 flex items-center gap-4 text-[11px]">
        <span className="text-text-muted">
          Tools:{" "}
          <span className="font-mono text-text-secondary">
            {state.toolCount}
          </span>
        </span>
        <span className="text-text-muted">
          Assets:{" "}
          <span className="font-mono text-text-secondary">
            {state.assetCount}
          </span>
        </span>
        {state.duration && (
          <span className="text-text-muted">
            Time:{" "}
            <span className="font-mono text-text-secondary">
              {state.duration}
            </span>
          </span>
        )}
      </div>

      {/* Action button */}
      <div className="mt-3">
        {state.status === "completed" && (
          <Link
            href="/campaign/findings"
            className="inline-flex items-center gap-1.5 rounded bg-neon-green/10 px-2.5 py-1 text-xs font-medium text-neon-green transition-colors hover:bg-neon-green/20"
          >
            <Eye className="h-3 w-3" />
            View Results
          </Link>
        )}
        {state.status === "active" && (
          <Link
            href="/campaign/c2"
            className="inline-flex items-center gap-1.5 rounded bg-neon-orange/10 px-2.5 py-1 text-xs font-medium text-neon-orange transition-colors hover:bg-neon-orange/20"
          >
            <Loader2 className="h-3 w-3 animate-spin" />
            Live View
          </Link>
        )}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Status badge                                                        */
/* ------------------------------------------------------------------ */

function StatusBadge({ status }: { status: PhaseStatus }) {
  if (status === "completed") {
    return (
      <span className="flex items-center gap-1 rounded-full bg-neon-green/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-neon-green">
        <CheckCircle2 className="h-3 w-3" />
        Done
      </span>
    );
  }
  if (status === "active") {
    return (
      <span className="flex items-center gap-1 rounded-full bg-neon-orange/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-neon-orange">
        <Loader2 className="h-3 w-3 animate-spin" />
        Active
      </span>
    );
  }
  return (
    <span className="rounded-full bg-bg-surface px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-text-muted">
      Pending
    </span>
  );
}

/* ------------------------------------------------------------------ */
/* Connector arrow (vertical between rows)                             */
/* ------------------------------------------------------------------ */

function ConnectorRow() {
  return (
    <div className="flex items-center justify-center gap-[calc(33.333%-2rem)] py-1">
      {[0, 1, 2].map((i) => (
        <div key={i} className="flex flex-col items-center">
          <div className="h-4 w-px bg-border-accent" />
          <div className="h-0 w-0 border-l-[4px] border-r-[4px] border-t-[5px] border-l-transparent border-r-transparent border-t-border-accent" />
        </div>
      ))}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Main page                                                           */
/* ------------------------------------------------------------------ */

export default function FlowPage() {
  const { activeTarget, jobs: storeJobs } = useCampaignStore();
  const [jobs, setJobs] = useState<JobState[]>(storeJobs);
  const [loading, setLoading] = useState(!!activeTarget);

  useEffect(() => {
    if (!activeTarget) return;
    let cancelled = false;
    setLoading(true);
    api
      .getStatus(activeTarget.id)
      .then((res) => {
        if (!cancelled) setJobs(res.jobs);
      })
      .catch(() => {})
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    const interval = setInterval(() => {
      api
        .getStatus(activeTarget.id)
        .then((res) => {
          if (!cancelled) setJobs(res.jobs);
        })
        .catch(() => {});
    }, 10_000);

    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [activeTarget]);

  const phaseStates = useMemo(() => derivePhaseStates(jobs), [jobs]);

  // Split phases into rows of 3
  const rows = useMemo(() => {
    const result: PhaseDef[][] = [];
    for (let i = 0; i < PHASES.length; i += 3) {
      result.push(PHASES.slice(i, i + 3));
    }
    return result;
  }, []);

  // Summary stats
  const completedCount = Object.values(phaseStates).filter(
    (s) => s.status === "completed",
  ).length;
  const activeCount = Object.values(phaseStates).filter(
    (s) => s.status === "active",
  ).length;
  const progress = Math.round((completedCount / PHASES.length) * 100);

  if (!activeTarget) {
    return (
      <div className="flex h-64 flex-col items-center justify-center gap-3">
        <Database className="h-10 w-10 text-text-muted" />
        <p className="text-text-muted">
          No active campaign. Launch one from the{" "}
          <Link href="/campaign" className="text-neon-orange underline">
            Campaign
          </Link>{" "}
          page.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-text-primary">Phase Flow</h1>
          <p className="mt-1 text-sm text-text-secondary">
            12-phase pipeline execution for{" "}
            <span className="font-mono text-neon-orange">
              {activeTarget.base_domain}
            </span>
          </p>
        </div>
        <div className="flex items-center gap-3 text-xs">
          <span className="text-text-muted">
            Completed:{" "}
            <span className="font-mono text-neon-green">{completedCount}</span>
          </span>
          <span className="text-text-muted">
            Active:{" "}
            <span className="font-mono text-neon-orange">{activeCount}</span>
          </span>
          <span className="text-text-muted">
            Pending:{" "}
            <span className="font-mono text-text-secondary">
              {PHASES.length - completedCount - activeCount}
            </span>
          </span>
        </div>
      </div>

      {/* Global progress bar */}
      <div>
        <div className="mb-1 flex items-center justify-between">
          <span className="section-label">Pipeline Progress</span>
          <span className="font-mono text-xs text-text-secondary">
            {progress}%
          </span>
        </div>
        <div className="progress-bar">
          <div className="progress-fill" style={{ width: `${progress}%` }} />
        </div>
      </div>

      {/* Loading state */}
      {loading && (
        <div className="flex h-32 items-center justify-center">
          <Loader2 className="h-5 w-5 animate-spin text-neon-orange" />
        </div>
      )}

      {/* Phase grid: 3 columns x 4 rows */}
      {!loading && (
        <div className="space-y-1">
          {rows.map((row, rowIdx) => (
            <div key={rowIdx}>
              {rowIdx > 0 && <ConnectorRow />}
              <div className="grid grid-cols-3 gap-4">
                {row.map((phase) => (
                  <PhaseCard
                    key={phase.id}
                    phase={phase}
                    state={phaseStates[phase.id]}
                  />
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Bottom action buttons */}
      {!loading && (
        <div className="flex items-center gap-3 border-t border-border pt-4">
          <button
            className="inline-flex items-center gap-2 rounded-md border border-border bg-bg-surface px-4 py-2 text-xs font-medium text-text-secondary transition-colors hover:border-neon-orange/40 hover:text-neon-orange"
            onClick={() => {
              /* placeholder: skip to phase action */
            }}
          >
            <SkipForward className="h-3.5 w-3.5" />
            Skip to Phase
          </button>
          <button
            className="inline-flex items-center gap-2 rounded-md border border-border bg-bg-surface px-4 py-2 text-xs font-medium text-text-secondary transition-colors hover:border-warning/40 hover:text-warning"
            onClick={() => {
              /* placeholder: pause pipeline action */
            }}
          >
            <Pause className="h-3.5 w-3.5" />
            Pause Pipeline
          </button>
          <div className="ml-auto text-[11px] text-text-muted">
            Last updated:{" "}
            <span className="font-mono text-text-secondary">
              {new Date().toLocaleTimeString()}
            </span>
          </div>
        </div>
      )}
    </div>
  );
}
