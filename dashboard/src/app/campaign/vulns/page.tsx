"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Loader2 } from "lucide-react";
import { type ColumnDef } from "@tanstack/react-table";
import DataTable from "@/components/findings/DataTable";
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

const SEV_COLORS: Record<VulnSeverity, string> = {
  critical: "bg-critical/20 text-critical",
  high: "bg-danger/20 text-danger",
  medium: "bg-warning/20 text-warning",
  low: "bg-info/20 text-info",
  info: "bg-bg-surface text-text-muted",
};

const columns: ColumnDef<VulnRow, unknown>[] = [
  { accessorKey: "id", header: "ID", size: 60 },
  {
    accessorKey: "severity",
    header: "Severity",
    cell: ({ getValue }) => {
      const s = getValue() as VulnSeverity;
      return (
        <span
          className={`rounded px-2 py-0.5 text-xs font-medium ${SEV_COLORS[s] ?? ""}`}
        >
          {s.toUpperCase()}
        </span>
      );
    },
  },
  { accessorKey: "title", header: "Title" },
  { accessorKey: "asset_value", header: "Asset" },
  { accessorKey: "source_tool", header: "Source" },
  {
    accessorKey: "created_at",
    header: "Found",
    cell: ({ getValue }) => {
      const v = getValue() as string | null;
      return v ? new Date(v).toLocaleString() : "—";
    },
  },
];

const TABS = ["all", "critical", "high", "medium", "low", "info"] as const;

export default function VulnsPage() {
  const router = useRouter();
  const { activeTarget } = useCampaignStore();
  const [data, setData] = useState<VulnRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState<(typeof TABS)[number]>("all");
  const [expanded, setExpanded] = useState<number | null>(null);

  useEffect(() => {
    if (!activeTarget) {
      router.push("/");
      return;
    }
    let cancelled = false;
    const severity = tab === "all" ? undefined : tab;
    api
      .getVulnerabilities(activeTarget.id, severity)
      .then((res) => {
        if (!cancelled) setData(res.vulnerabilities as VulnRow[]);
      })
      .catch(() => {})
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => { cancelled = true; };
  }, [activeTarget, tab, router]);

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold text-text-primary">Vulnerabilities</h1>
      <p className="text-sm text-text-secondary">
        Findings grouped by severity
      </p>

      {/* Severity tabs */}
      <div className="flex gap-1">
        {TABS.map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`rounded-md px-3 py-1 text-xs font-medium transition-colors ${
              tab === t
                ? "bg-accent/20 text-accent"
                : "text-text-muted hover:bg-bg-surface hover:text-text-primary"
            }`}
          >
            {t.charAt(0).toUpperCase() + t.slice(1)}
          </button>
        ))}
      </div>

      {loading ? (
        <div className="flex h-32 items-center justify-center">
          <Loader2 className="h-5 w-5 animate-spin text-accent" />
        </div>
      ) : (
        <>
          <DataTable data={data} columns={columns} />

          {/* Expandable detail panel — simple click-to-expand */}
          {expanded !== null && (() => {
            const vuln = data.find((v) => v.id === expanded);
            if (!vuln) return null;
            return (
              <div className="rounded-lg border border-border bg-bg-secondary p-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-semibold text-text-primary">
                    {vuln.title}
                  </h3>
                  <button
                    onClick={() => setExpanded(null)}
                    className="text-xs text-text-muted hover:text-text-primary"
                  >
                    Close
                  </button>
                </div>
                {vuln.description && (
                  <p className="mt-2 text-xs text-text-secondary">
                    {vuln.description}
                  </p>
                )}
                {vuln.poc && (
                  <pre className="mt-2 overflow-x-auto rounded bg-bg-tertiary p-2 text-xs text-text-primary">
                    {vuln.poc}
                  </pre>
                )}
                <div className="mt-3 border-t border-border pt-3">
                  <DraftReportButton vulnId={vuln.id} />
                </div>
              </div>
            );
          })()}
        </>
      )}
    </div>
  );
}
