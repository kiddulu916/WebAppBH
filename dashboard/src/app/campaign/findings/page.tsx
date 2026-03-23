"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  Globe,
  Shield,
  Cloud,
  Database,
  Loader2,
} from "lucide-react";
import CorrelationView from "@/components/findings/CorrelationView";
import DataTable from "@/components/findings/DataTable";
import { api } from "@/lib/api";
import { useCampaignStore } from "@/stores/campaign";
import type { AssetWithLocations } from "@/lib/api";
import type { VulnSeverity } from "@/types/schema";
import { type ColumnDef } from "@tanstack/react-table";

/* ── Unified row for the DataTable ── */

interface UnifiedRow {
  id: string;
  category: "asset" | "vuln" | "cloud";
  label: string;
  detail: string;
  source: string;
  created_at: string | null;
}

const columns: ColumnDef<UnifiedRow, unknown>[] = [
  {
    accessorKey: "category",
    header: "Category",
    cell: ({ getValue }) => {
      const c = getValue() as string;
      const styles: Record<string, string> = {
        asset: "bg-neon-blue-glow text-neon-blue border-neon-blue/20",
        vuln: "bg-neon-orange-glow text-neon-orange border-neon-orange/20",
        cloud: "bg-neon-green-glow text-neon-green border-neon-green/20",
      };
      return (
        <span
          className={`inline-block rounded border px-2 py-0.5 text-xs font-medium ${styles[c] ?? ""}`}
        >
          {c}
        </span>
      );
    },
  },
  { accessorKey: "label", header: "Name" },
  {
    accessorKey: "detail",
    header: "Detail",
    cell: ({ getValue }) => (
      <span className="font-mono text-xs text-text-secondary">
        {getValue() as string}
      </span>
    ),
  },
  {
    accessorKey: "source",
    header: "Source",
    cell: ({ getValue }) => (
      <span className="font-mono text-xs text-text-muted">
        {getValue() as string}
      </span>
    ),
  },
  {
    accessorKey: "created_at",
    header: "Found",
    cell: ({ getValue }) => {
      const v = getValue() as string | null;
      return (
        <span className="font-mono text-xs text-text-muted">
          {v ? new Date(v).toLocaleString() : "—"}
        </span>
      );
    },
  },
];

/* ── Category nav cards ── */

const CATEGORIES = [
  {
    key: "assets",
    label: "Assets",
    icon: Globe,
    href: "/campaign/assets",
    color: "text-neon-blue",
  },
  {
    key: "vulns",
    label: "Vulnerabilities",
    icon: Shield,
    href: "/campaign/vulns",
    color: "text-neon-orange",
  },
  {
    key: "cloud",
    label: "Cloud",
    icon: Cloud,
    href: "/campaign/cloud",
    color: "text-neon-green",
  },
] as const;

export default function FindingsPage() {
  const activeTarget = useCampaignStore((s) => s.activeTarget);
  const [rows, setRows] = useState<UnifiedRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [counts, setCounts] = useState({ assets: 0, vulns: 0, cloud: 0 });

  useEffect(() => {
    if (!activeTarget) {
      setLoading(false);
      return;
    }

    let cancelled = false;

    async function fetchAll() {
      try {
        const [assetsRes, vulnsRes, cloudRes] = await Promise.all([
          api.getAssets(activeTarget!.id),
          api.getVulnerabilities(activeTarget!.id),
          api.getCloudAssets(activeTarget!.id),
        ]);

        if (cancelled) return;

        const unified: UnifiedRow[] = [];

        for (const a of assetsRes.assets) {
          unified.push({
            id: `a-${a.id}`,
            category: "asset",
            label: a.asset_value,
            detail: a.asset_type,
            source: a.source_tool ?? "—",
            created_at: a.created_at,
          });
        }

        for (const v of vulnsRes.vulnerabilities) {
          unified.push({
            id: `v-${v.id}`,
            category: "vuln",
            label: v.title,
            detail: `${(v.severity as VulnSeverity).toUpperCase()} — ${v.asset_value ?? "N/A"}`,
            source: v.source_tool ?? "—",
            created_at: v.created_at,
          });
        }

        for (const c of cloudRes.cloud_assets) {
          unified.push({
            id: `c-${c.id}`,
            category: "cloud",
            label: c.asset_type,
            detail: `${c.provider} — ${c.url ?? "no url"}`,
            source: c.is_public ? "PUBLIC" : "private",
            created_at: c.created_at,
          });
        }

        setCounts({
          assets: assetsRes.assets.length,
          vulns: vulnsRes.vulnerabilities.length,
          cloud: cloudRes.cloud_assets.length,
        });
        setRows(unified);
      } catch {
        /* noop */
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    fetchAll();
    return () => {
      cancelled = true;
    };
  }, [activeTarget]);

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div>
        <h1 className="flex items-center gap-2 text-2xl font-bold text-text-primary">
          <Database className="h-5 w-5 text-neon-blue" />
          All Findings
        </h1>
        <p className="mt-1 text-sm text-text-secondary">
          Browse all discovered data across every phase
        </p>
      </div>

      {/* Count badges */}
      <div className="flex flex-wrap gap-3">
        <span className="rounded-md border border-border bg-bg-surface px-3 py-1 text-xs text-text-secondary">
          Assets{" "}
          <span className="font-mono text-neon-blue">{counts.assets}</span>
        </span>
        <span className="rounded-md border border-border bg-bg-surface px-3 py-1 text-xs text-text-secondary">
          Vulns{" "}
          <span className="font-mono text-neon-orange">{counts.vulns}</span>
        </span>
        <span className="rounded-md border border-border bg-bg-surface px-3 py-1 text-xs text-text-secondary">
          Cloud{" "}
          <span className="font-mono text-neon-green">{counts.cloud}</span>
        </span>
        <span className="rounded-md border border-border bg-bg-surface px-3 py-1 text-xs text-text-secondary">
          Total{" "}
          <span className="font-mono text-text-primary">
            {counts.assets + counts.vulns + counts.cloud}
          </span>
        </span>
      </div>

      {/* Category cards */}
      <div className="grid grid-cols-3 gap-4">
        {CATEGORIES.map(({ key, label, icon: Icon, href, color }) => (
          <Link
            key={key}
            href={href}
            className="group flex items-center gap-4 rounded-lg border border-border bg-bg-secondary p-5 transition-all hover:border-neon-orange/40 hover:glow-orange"
          >
            <Icon className={`h-8 w-8 ${color}`} />
            <div>
              <h3 className="text-sm font-medium text-text-primary group-hover:text-neon-orange">
                {label}
              </h3>
              <p className="text-xs text-text-muted">
                View all {label.toLowerCase()}
              </p>
            </div>
          </Link>
        ))}
      </div>

      {/* Correlated findings */}
      <div>
        <p className="section-label mb-3">Correlation Analysis</p>
        <CorrelationView />
      </div>

      {/* Unified data table */}
      <div>
        <p className="section-label mb-3">All Data</p>
        {loading ? (
          <div className="flex h-32 items-center justify-center">
            <Loader2 className="h-5 w-5 animate-spin text-neon-orange" />
          </div>
        ) : (
          <DataTable data={rows} columns={columns} />
        )}
      </div>
    </div>
  );
}
