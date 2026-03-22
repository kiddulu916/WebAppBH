"use client";

import { useEffect, useState, useMemo, useCallback } from "react";
import { useRouter } from "next/navigation";
import {
  Loader2,
  Globe,
  Search,
  ArrowUpDown,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";
import { api } from "@/lib/api";
import { useCampaignStore } from "@/stores/campaign";

interface AssetRow {
  id: number;
  target_id: number;
  asset_type: string;
  asset_value: string;
  source_tool: string | null;
  created_at: string | null;
  updated_at: string | null;
}

const TYPE_BADGE: Record<string, string> = {
  subdomain: "bg-neon-blue-glow text-neon-blue border-neon-blue/20",
  ip: "bg-neon-orange-glow text-neon-orange border-neon-orange/20",
  cidr: "bg-neon-green-glow text-neon-green border-neon-green/20",
  url: "bg-bg-surface text-text-muted border-border",
};

type SortKey = "asset_type" | "asset_value" | "source_tool" | "created_at";
type SortDir = "asc" | "desc";

const PAGE_SIZE = 25;

export default function AssetsPage() {
  const router = useRouter();
  const activeTarget = useCampaignStore((s) => s.activeTarget);
  const [data, setData] = useState<AssetRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>("created_at");
  const [sortDir, setSortDir] = useState<SortDir>("desc");
  const [page, setPage] = useState(0);

  useEffect(() => {
    if (!activeTarget) {
      router.push("/");
      return;
    }
    api
      .getAssets(activeTarget.id)
      .then((res) => setData(res.assets))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [activeTarget, router]);

  const toggleSort = useCallback(
    (key: SortKey) => {
      if (sortKey === key) {
        setSortDir((d) => (d === "asc" ? "desc" : "asc"));
      } else {
        setSortKey(key);
        setSortDir("asc");
      }
      setPage(0);
    },
    [sortKey],
  );

  const filtered = useMemo(() => {
    let rows = data;
    if (search) {
      const q = search.toLowerCase();
      rows = rows.filter((r) => r.asset_value.toLowerCase().includes(q));
    }
    rows = [...rows].sort((a, b) => {
      const av = a[sortKey] ?? "";
      const bv = b[sortKey] ?? "";
      const cmp = String(av).localeCompare(String(bv));
      return sortDir === "asc" ? cmp : -cmp;
    });
    return rows;
  }, [data, search, sortKey, sortDir]);

  const pageCount = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const paged = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

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
      <div className="flex items-center justify-between">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-bold text-text-primary">
            <Globe className="h-5 w-5 text-neon-blue" />
            Assets
          </h1>
          <p className="mt-1 text-sm text-text-secondary">
            Discovered subdomains, IPs, and CIDRs
          </p>
        </div>
        <span className="rounded-md border border-border bg-bg-surface px-3 py-1 font-mono text-sm text-text-primary">
          {filtered.length}
        </span>
      </div>

      {/* Search */}
      <div className="relative">
        <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-text-muted" />
        <input
          value={search}
          onChange={(e) => {
            setSearch(e.target.value);
            setPage(0);
          }}
          placeholder="Filter by value..."
          className="w-full rounded-md border border-border bg-bg-tertiary py-2 pl-9 pr-3 text-sm text-text-primary placeholder:text-text-muted input-focus"
        />
      </div>

      {/* Table */}
      {loading ? (
        <div className="flex h-32 items-center justify-center">
          <Loader2 className="h-5 w-5 animate-spin text-neon-orange" />
        </div>
      ) : (
        <>
          <div className="overflow-x-auto rounded-lg border border-border">
            <table className="w-full text-left text-sm">
              <thead className="bg-bg-surface text-xs text-text-secondary">
                <tr>
                  <SortHeader
                    label="Type"
                    field="asset_type"
                    current={sortKey}
                    dir={sortDir}
                    onSort={toggleSort}
                  />
                  <SortHeader
                    label="Value"
                    field="asset_value"
                    current={sortKey}
                    dir={sortDir}
                    onSort={toggleSort}
                  />
                  <SortHeader
                    label="Source Tool"
                    field="source_tool"
                    current={sortKey}
                    dir={sortDir}
                    onSort={toggleSort}
                  />
                  <SortHeader
                    label="Discovered At"
                    field="created_at"
                    current={sortKey}
                    dir={sortDir}
                    onSort={toggleSort}
                  />
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {paged.length === 0 ? (
                  <tr>
                    <td
                      colSpan={4}
                      className="px-4 py-8 text-center text-text-muted"
                    >
                      No assets found
                    </td>
                  </tr>
                ) : (
                  paged.map((row) => (
                    <tr
                      key={row.id}
                      className="bg-bg-secondary transition-colors hover:bg-bg-tertiary"
                    >
                      <td className="px-4 py-2.5">
                        <span
                          className={`inline-block rounded border px-2 py-0.5 text-xs font-medium ${
                            TYPE_BADGE[row.asset_type] ?? TYPE_BADGE.url
                          }`}
                        >
                          {row.asset_type}
                        </span>
                      </td>
                      <td className="px-4 py-2.5 font-mono text-text-primary">
                        {row.asset_value}
                      </td>
                      <td className="px-4 py-2.5 font-mono text-xs text-text-secondary">
                        {row.source_tool ?? "—"}
                      </td>
                      <td className="px-4 py-2.5 font-mono text-xs text-text-muted">
                        {row.created_at
                          ? new Date(row.created_at).toLocaleString()
                          : "—"}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          <div className="flex items-center justify-between text-xs text-text-muted">
            <span>{filtered.length} result(s)</span>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setPage((p) => Math.max(0, p - 1))}
                disabled={page === 0}
                className="rounded p-1 hover:bg-bg-surface disabled:opacity-30"
              >
                <ChevronLeft className="h-4 w-4" />
              </button>
              <span className="font-mono">
                {page + 1} / {pageCount}
              </span>
              <button
                onClick={() => setPage((p) => Math.min(pageCount - 1, p + 1))}
                disabled={page >= pageCount - 1}
                className="rounded p-1 hover:bg-bg-surface disabled:opacity-30"
              >
                <ChevronRight className="h-4 w-4" />
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

/* ── Sort Header ── */

function SortHeader({
  label,
  field,
  current,
  dir,
  onSort,
}: {
  label: string;
  field: SortKey;
  current: SortKey;
  dir: SortDir;
  onSort: (k: SortKey) => void;
}) {
  const active = current === field;
  return (
    <th className="px-4 py-3 font-medium">
      <button
        className="flex items-center gap-1"
        onClick={() => onSort(field)}
      >
        {label}
        <ArrowUpDown
          className={`h-3 w-3 ${active ? "text-neon-orange" : "text-text-muted"}`}
        />
        {active && (
          <span className="text-[10px] text-neon-orange">
            {dir === "asc" ? "↑" : "↓"}
          </span>
        )}
      </button>
    </th>
  );
}
