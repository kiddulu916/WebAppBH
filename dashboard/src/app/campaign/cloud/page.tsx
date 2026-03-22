"use client";

import { useEffect, useState, useMemo } from "react";
import { useRouter } from "next/navigation";
import {
  Loader2,
  Cloud,
  ChevronDown,
  ChevronUp,
  X,
} from "lucide-react";
import { api } from "@/lib/api";
import { useCampaignStore } from "@/stores/campaign";
import type { CloudAsset, CloudProvider } from "@/types/schema";

const PROVIDERS: CloudProvider[] = ["AWS", "Azure", "GCP", "Other"];

const PROVIDER_BADGE: Record<CloudProvider, string> = {
  AWS: "bg-neon-orange-glow text-neon-orange border-neon-orange/20",
  Azure: "bg-neon-blue-glow text-neon-blue border-neon-blue/20",
  GCP: "bg-sev-high/15 text-sev-high border-sev-high/25",
  Other: "bg-bg-surface text-text-muted border-border",
};

export default function CloudPage() {
  const router = useRouter();
  const activeTarget = useCampaignStore((s) => s.activeTarget);
  const [data, setData] = useState<CloudAsset[]>([]);
  const [loading, setLoading] = useState(true);
  const [providerFilter, setProviderFilter] = useState<CloudProvider | null>(
    null,
  );
  const [expanded, setExpanded] = useState<number | null>(null);

  useEffect(() => {
    if (!activeTarget) {
      router.push("/");
      return;
    }
    api
      .getCloudAssets(activeTarget.id)
      .then((res) => setData(res.cloud_assets))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [activeTarget, router]);

  /* Provider counts */
  const providerCounts = useMemo(() => {
    const counts: Record<CloudProvider, number> = {
      AWS: 0,
      Azure: 0,
      GCP: 0,
      Other: 0,
    };
    for (const c of data) {
      const p = counts[c.provider] !== undefined ? c.provider : "Other";
      counts[p]++;
    }
    return counts;
  }, [data]);

  /* Filtered data */
  const filtered = useMemo(() => {
    if (!providerFilter) return data;
    return data.filter((c) => c.provider === providerFilter);
  }, [data, providerFilter]);

  /* Findings count helper */
  const findingsCount = (c: CloudAsset) => {
    if (!c.findings) return 0;
    if (Array.isArray(c.findings)) return c.findings.length;
    return Object.keys(c.findings).length;
  };

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
          <Cloud className="h-5 w-5 text-neon-blue" />
          Cloud Assets
        </h1>
        <p className="mt-1 text-sm text-text-secondary">
          AWS, Azure, and GCP resource findings
        </p>
      </div>

      {/* Provider distribution */}
      <div className="flex flex-wrap gap-2">
        {PROVIDERS.map((p) => {
          const isActive = providerFilter === p;
          return (
            <button
              key={p}
              onClick={() => setProviderFilter(isActive ? null : p)}
              className={`flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-xs font-medium transition-all ${
                isActive
                  ? PROVIDER_BADGE[p] + " ring-1 ring-current"
                  : PROVIDER_BADGE[p] + " opacity-70 hover:opacity-100"
              }`}
            >
              {p}
              <span className="font-mono">{providerCounts[p]}</span>
            </button>
          );
        })}
        {providerFilter && (
          <button
            onClick={() => setProviderFilter(null)}
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
                <th className="px-4 py-3 font-medium">Provider</th>
                <th className="px-4 py-3 font-medium">Type</th>
                <th className="px-4 py-3 font-medium">URL</th>
                <th className="px-4 py-3 font-medium">Public</th>
                <th className="px-4 py-3 font-medium">Findings</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {filtered.length === 0 ? (
                <tr>
                  <td
                    colSpan={6}
                    className="px-4 py-8 text-center text-text-muted"
                  >
                    No cloud assets found
                  </td>
                </tr>
              ) : (
                filtered.map((c) => {
                  const isOpen = expanded === c.id;
                  return (
                    <CloudRowItem
                      key={c.id}
                      asset={c}
                      findingsCount={findingsCount(c)}
                      isOpen={isOpen}
                      onToggle={() =>
                        setExpanded(isOpen ? null : c.id)
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

/* ── Cloud Row with expandable findings ── */

function CloudRowItem({
  asset,
  findingsCount,
  isOpen,
  onToggle,
}: {
  asset: CloudAsset;
  findingsCount: number;
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
          <span
            className={`inline-block rounded border px-2 py-0.5 text-xs font-medium ${
              PROVIDER_BADGE[asset.provider] ?? PROVIDER_BADGE.Other
            }`}
          >
            {asset.provider}
          </span>
        </td>
        <td className="px-4 py-2.5 font-mono text-xs text-text-primary">
          {asset.asset_type}
        </td>
        <td className="px-4 py-2.5">
          {asset.url ? (
            <span
              className="inline-block max-w-xs truncate font-mono text-xs text-text-secondary"
              title={asset.url}
            >
              {asset.url}
            </span>
          ) : (
            <span className="text-text-muted">—</span>
          )}
        </td>
        <td className="px-4 py-2.5">
          {asset.is_public ? (
            <span className="inline-flex items-center gap-1">
              <span className="inline-block h-2 w-2 rounded-full bg-danger" />
              <span className="text-xs font-medium text-danger">Yes</span>
            </span>
          ) : (
            <span className="inline-flex items-center gap-1">
              <span className="inline-block h-2 w-2 rounded-full bg-success" />
              <span className="text-xs font-medium text-success">No</span>
            </span>
          )}
        </td>
        <td className="px-4 py-2.5 font-mono text-xs text-text-muted">
          {findingsCount}
        </td>
      </tr>
      {isOpen && asset.findings && (
        <tr className="animate-fade-in">
          <td colSpan={6} className="bg-bg-tertiary px-6 py-4">
            <p className="section-label mb-2">Findings JSON</p>
            <pre className="overflow-x-auto rounded-md border border-border bg-bg-void p-3 font-mono text-xs text-text-code">
              {JSON.stringify(asset.findings, null, 2)}
            </pre>
          </td>
        </tr>
      )}
    </>
  );
}
