"use client";

import { useEffect, useState, useMemo } from "react";
import { useRouter } from "next/navigation";
import { Loader2, Shield, ChevronDown, ChevronUp, X } from "lucide-react";
import DraftReportButton from "@/components/vulns/DraftReportButton";
import { api } from "@/lib/api";
import { useCampaignStore } from "@/stores/campaign";
import type { VulnSeverity } from "@/types/schema";

interface VulnRow {
  id: number;
  target_id: number;
  asset_id: number | null;
  asset_value: string | null;
  severity: VulnSeverity;
  title: string;
  description: string | null;
  poc: string | null;
  source_tool: string | null;
  created_at: string | null;
  updated_at: string | null;
}

const SEVERITIES: VulnSeverity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

const SEV_PILL: Record<VulnSeverity, string> = {
  critical: "bg-sev-critical/15 text-sev-critical border-sev-critical/25",
  high: "bg-sev-high/15 text-sev-high border-sev-high/25",
  medium: "bg-sev-medium/15 text-sev-medium border-sev-medium/25",
  low: "bg-sev-low/15 text-sev-low border-sev-low/25",
  info: "bg-bg-surface text-text-muted border-border",
};

const SEV_DOT: Record<VulnSeverity, string> = {
  critical: "bg-sev-critical",
  high: "bg-sev-high",
  medium: "bg-sev-medium",
  low: "bg-sev-low",
  info: "bg-text-muted",
};

export default function VulnsPage() {
  const router = useRouter();
  const activeTarget = useCampaignStore((s) => s.activeTarget);
  const [allData, setAllData] = useState<VulnRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeSev, setActiveSev] = useState<VulnSeverity | null>(null);
  const [expanded, setExpanded] = useState<number | null>(null);

  useEffect(() => {
    if (!activeTarget) {
      router.push("/");
      return;
    }
    let cancelled = false;
    api
      .getVulnerabilities(activeTarget.id)
      .then((res) => {
        if (!cancelled) setAllData(res.vulnerabilities as VulnRow[]);
      })
      .catch(() => {})
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [activeTarget, router]);

  /* Severity counts */
  const sevCounts = useMemo(() => {
    const counts: Record<VulnSeverity, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };
    for (const v of allData) {
      if (counts[v.severity] !== undefined) counts[v.severity]++;
    }
    return counts;
  }, [allData]);

  /* Filtered data */
  const filtered = useMemo(() => {
    if (!activeSev) return allData;
    return allData.filter((v) => v.severity === activeSev);
  }, [allData, activeSev]);

  if (!activeTarget) {
    return (
      <div className="flex h-64 items-center justify-center">
        <p className="text-text-muted">No active campaign selected.</p>
      </div>
    );
  }

  return (
    <div className="space-y-5 animate-fade-in">
      {/* Header */}
      <div>
        <h1 className="flex items-center gap-2 text-2xl font-bold text-text-primary">
          <Shield className="h-5 w-5 text-neon-orange" />
          Vulnerabilities
        </h1>
        <p className="mt-1 text-sm text-text-secondary">
          Findings grouped by severity
        </p>
      </div>

      {/* Severity distribution pills */}
      <div className="flex flex-wrap gap-2">
        {SEVERITIES.map((sev) => {
          const isActive = activeSev === sev;
          return (
            <button
              key={sev}
              onClick={() => setActiveSev(isActive ? null : sev)}
              className={`flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-xs font-medium transition-all ${
                isActive
                  ? SEV_PILL[sev] + " ring-1 ring-current"
                  : SEV_PILL[sev] + " opacity-70 hover:opacity-100"
              }`}
            >
              <span
                className={`inline-block h-2 w-2 rounded-full ${SEV_DOT[sev]}`}
              />
              {sev.charAt(0).toUpperCase() + sev.slice(1)}
              <span className="font-mono">{sevCounts[sev]}</span>
            </button>
          );
        })}
        {activeSev && (
          <button
            onClick={() => setActiveSev(null)}
            className="flex items-center gap-1 rounded-md border border-border px-2 py-1.5 text-xs text-text-muted hover:text-text-primary"
          >
            <X className="h-3 w-3" />
            Clear
          </button>
        )}
      </div>

      {/* Table */}
      {loading ? (
        <div className="flex h-32 items-center justify-center">
          <Loader2 className="h-5 w-5 animate-spin text-neon-orange" />
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-left text-sm">
            <thead className="bg-bg-surface text-xs text-text-secondary">
              <tr>
                <th className="w-8 px-4 py-3" />
                <th className="px-4 py-3 font-medium">Severity</th>
                <th className="px-4 py-3 font-medium">Title</th>
                <th className="px-4 py-3 font-medium">Asset</th>
                <th className="px-4 py-3 font-medium">Source</th>
                <th className="px-4 py-3 font-medium">Found At</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {filtered.length === 0 ? (
                <tr data-testid="vulns-empty-state">
                  <td
                    colSpan={6}
                    className="px-4 py-8 text-center text-text-muted"
                  >
                    No vulnerabilities found
                  </td>
                </tr>
              ) : (
                filtered.map((vuln) => {
                  const isOpen = expanded === vuln.id;
                  return (
                    <VulnRowItem
                      key={vuln.id}
                      vuln={vuln}
                      isOpen={isOpen}
                      onToggle={() =>
                        setExpanded(isOpen ? null : vuln.id)
                      }
                    />
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

/* ── Vuln Row with expandable detail ── */

function VulnRowItem({
  vuln,
  isOpen,
  onToggle,
}: {
  vuln: VulnRow;
  isOpen: boolean;
  onToggle: () => void;
}) {
  return (
    <>
      <tr
        onClick={onToggle}
        className="cursor-pointer bg-bg-secondary transition-colors hover:bg-bg-tertiary"
      >
        <td className="px-4 py-2.5 text-text-muted">
          {isOpen ? (
            <ChevronUp className="h-3.5 w-3.5" />
          ) : (
            <ChevronDown className="h-3.5 w-3.5" />
          )}
        </td>
        <td className="px-4 py-2.5">
          <span className="flex items-center gap-1.5">
            <span
              className={`inline-block h-2.5 w-2.5 rounded-full ${SEV_DOT[vuln.severity]}`}
            />
            <span className="text-xs font-medium text-text-secondary">
              {vuln.severity.toUpperCase()}
            </span>
          </span>
        </td>
        <td className="px-4 py-2.5 text-text-primary">{vuln.title}</td>
        <td className="px-4 py-2.5 font-mono text-xs text-text-secondary">
          {vuln.asset_value ?? "—"}
        </td>
        <td className="px-4 py-2.5 font-mono text-xs text-text-muted">
          {vuln.source_tool ?? "—"}
        </td>
        <td className="px-4 py-2.5 font-mono text-xs text-text-muted">
          {vuln.created_at
            ? new Date(vuln.created_at).toLocaleString()
            : "—"}
        </td>
      </tr>
      {isOpen && (
        <tr className="animate-fade-in">
          <td colSpan={6} className="bg-bg-tertiary px-6 py-4">
            {vuln.description && (
              <p className="mb-3 text-xs text-text-secondary">
                {vuln.description}
              </p>
            )}
            {vuln.poc && (
              <div className="mb-3">
                <p className="section-label mb-1">Proof of Concept</p>
                <pre className="overflow-x-auto rounded-md border border-border bg-bg-void p-3 font-mono text-xs text-text-code">
                  {vuln.poc}
                </pre>
              </div>
            )}
            <div className="border-t border-border pt-3">
              <DraftReportButton vulnId={vuln.id} />
            </div>
          </td>
        </tr>
      )}
    </>
  );
}
