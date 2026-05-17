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
  RefreshCw,
  AlertTriangle,
  CheckSquare,
  Square,
  MinusSquare,
  ShieldCheck,
  ShieldOff,
} from "lucide-react";
import { api, type AssetWithLocations } from "@/lib/api";
import { useCampaignStore } from "@/stores/campaign";

/* ── Constants ── */

const PAGE_SIZE = 25;

const TYPE_BADGE: Record<string, string> = {
  domain: "bg-accent/10 text-accent border-accent/20",
  subdomain: "bg-neon-blue-glow text-neon-blue border-neon-blue/20",
  ip: "bg-neon-orange-glow text-neon-orange border-neon-orange/20",
  cidr: "bg-neon-green-glow text-neon-green border-neon-green/20",
  sensitive_file: "bg-danger/10 text-danger border-danger/20",
  directory: "bg-sev-medium/10 text-sev-medium border-sev-medium/20",
  error: "bg-danger/10 text-neon-orange border-neon-orange/20",
  form: "bg-neon-blue-glow text-neon-blue border-neon-blue/20",
  upload: "bg-sev-medium/10 text-sev-medium border-sev-medium/20",
  deadend: "bg-bg-surface text-text-muted border-border",
  undetermined: "bg-bg-surface text-text-secondary border-border",
  url: "bg-bg-surface text-text-muted border-border",
};


type SortKey = "asset_type" | "asset_value" | "source_tool" | "created_at" | "ports";
type SortDir = "asc" | "desc";
type TypeFilter = "all" | "domain" | "subdomain" | "ip" | "cidr" | "sensitive_file" | "directory" | "error" | "form" | "upload" | "deadend" | "undetermined";
type ClassFilter = "all" | "in_scope" | "out_of_scope" | "pending" | "associated" | "undetermined";

const CLASSIFICATION_BADGE: Record<string, string> = {
  in_scope: "bg-neon-green-glow text-neon-green border-neon-green/20",
  out_of_scope: "bg-danger/10 text-danger border-danger/20",
  pending: "bg-sev-medium/10 text-sev-medium border-sev-medium/20",
  associated: "bg-neon-blue-glow text-neon-blue border-neon-blue/20",
  undetermined: "bg-bg-surface text-text-muted border-border",
};

/* ── Helper: relative timestamp ── */

function relativeTime(iso: string | null): string {
  if (!iso) return "\u2014";
  const diff = Date.now() - new Date(iso).getTime();
  const seconds = Math.floor(diff / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

/* ── Helper: format ports ── */

function formatPorts(locations: AssetWithLocations["locations"]): { display: string; total: number } {
  const ports = locations.map((l) => l.port).filter((p) => p != null);
  const unique = [...new Set(ports)].sort((a, b) => a - b);
  if (unique.length === 0) return { display: "\u2014", total: 0 };
  if (unique.length <= 3) return { display: unique.join(", "), total: unique.length };
  return {
    display: `${unique.slice(0, 3).join(", ")} +${unique.length - 3} more`,
    total: unique.length,
  };
}

/* ── Main Page Component ── */

export default function AssetsPage() {
  const router = useRouter();
  const activeTarget = useCampaignStore((s) => s.activeTarget);

  /* ── Data state ── */
  const [data, setData] = useState<AssetWithLocations[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  /* ── Controls ── */
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState<TypeFilter>("all");
  const [classFilter, setClassFilter] = useState<ClassFilter>("all");
  const [sortKey, setSortKey] = useState<SortKey>("created_at");
  const [sortDir, setSortDir] = useState<SortDir>("desc");
  const [page, setPage] = useState(0);

  /* ── Selection state ── */
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [bulkLoading, setBulkLoading] = useState(false);

  /* ── Progress state ── */
  const [loadedCount, setLoadedCount] = useState(0);
  const [totalCount, setTotalCount] = useState(0);

  /* ── Fetch assets ── */
  const fetchData = useCallback(async () => {
    if (!activeTarget) return;
    setLoading(true);
    setError(false);
    setLoadedCount(0);
    setTotalCount(0);
    try {
      const assets = await api.getAllAssets(activeTarget.id, (loaded, total) => {
        setLoadedCount(loaded);
        setTotalCount(total);
      });
      setData(assets);
    } catch {
      setError(true);
    } finally {
      setLoading(false);
    }
  }, [activeTarget]);

  useEffect(() => {
    if (!activeTarget) {
      router.push("/");
      return;
    }
    fetchData();
  }, [activeTarget, router, fetchData]);

  /* ── Sort toggle ── */
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

  /* ── Selection helpers ── */
  const toggleSelect = useCallback((id: number) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  const handleBulkClassify = useCallback(
    async (classification: string) => {
      if (selected.size === 0) return;
      setBulkLoading(true);
      try {
        await api.bulkUpdateClassification([...selected], classification);
        // Update local data to reflect the change
        setData((prev) =>
          prev.map((a) =>
            selected.has(a.id) ? { ...a, scope_classification: classification } : a,
          ),
        );
        setSelected(new Set());
      } finally {
        setBulkLoading(false);
      }
    },
    [selected],
  );

  /* ── Filtering + sorting ── */
  const filtered = useMemo(() => {
    let rows = data;

    // Type filter
    if (typeFilter !== "all") {
      rows = rows.filter((r) => r.asset_type === typeFilter);
    }

    // Classification filter
    if (classFilter !== "all") {
      rows = rows.filter((r) => r.scope_classification === classFilter);
    }

    // Text search
    if (search) {
      const q = search.toLowerCase();
      rows = rows.filter((r) => r.asset_value.toLowerCase().includes(q));
    }

    // Sort
    rows = [...rows].sort((a, b) => {
      let cmp = 0;
      switch (sortKey) {
        case "ports": {
          cmp = a.locations.length - b.locations.length;
          break;
        }
        default: {
          const av = a[sortKey as keyof AssetWithLocations] ?? "";
          const bv = b[sortKey as keyof AssetWithLocations] ?? "";
          cmp = String(av).localeCompare(String(bv));
        }
      }
      return sortDir === "asc" ? cmp : -cmp;
    });

    return rows;
  }, [data, search, typeFilter, classFilter, sortKey, sortDir]);

  /* ── Pagination ── */
  const pageCount = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const paged = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  /* ── Select-all state for current page ── */
  const allPageSelected = paged.length > 0 && paged.every((r) => selected.has(r.id));
  const somePageSelected = paged.some((r) => selected.has(r.id));

  const toggleSelectAll = useCallback(() => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (allPageSelected) {
        // Deselect all on this page
        for (const r of paged) next.delete(r.id);
      } else {
        // Select all on this page
        for (const r of paged) next.add(r.id);
      }
      return next;
    });
  }, [allPageSelected, paged]);

  /* ── Row selection helper ── */
  const isSelected = (id: number) => selected.has(id);

  /* ── No active target guard ── */
  if (!activeTarget) {
    return (
      <div className="flex h-64 items-center justify-center">
        <p className="text-text-muted">No active campaign selected.</p>
      </div>
    );
  }

  /* ── Error state ── */
  if (error && !loading) {
    return (
      <div className="space-y-5 animate-fade-in">
        <PageHeader count={0} />
        <div
          data-testid="assets-error-state"
          className="flex flex-col items-center justify-center gap-4 rounded-lg border border-danger/30 bg-danger/5 py-16"
        >
          <AlertTriangle className="h-10 w-10 text-danger" />
          <p className="text-text-primary font-medium">Failed to load assets.</p>
          <button
            data-testid="assets-retry-btn"
            onClick={fetchData}
            className="flex items-center gap-2 rounded-md border border-border bg-bg-surface px-4 py-2 text-sm text-text-primary transition-colors hover:bg-bg-tertiary"
          >
            <RefreshCw className="h-4 w-4" />
            Retry
          </button>
        </div>
      </div>
    );
  }

  /* ── Loading state ── */
  if (loading) {
    return (
      <div className="space-y-5 animate-fade-in">
        <PageHeader count={0} />
        <div className="flex h-64 items-center justify-center gap-3">
          <Loader2 className="h-6 w-6 animate-spin text-neon-orange" />
          {totalCount > 0 && (
            <span className="text-sm text-text-muted font-mono">
              Loading {loadedCount} / {totalCount}…
            </span>
          )}
        </div>
      </div>
    );
  }

  /* ── Empty state ── */
  if (data.length === 0) {
    return (
      <div className="space-y-5 animate-fade-in">
        <PageHeader count={0} />
        <div
          data-testid="assets-empty-state"
          className="flex flex-col items-center justify-center gap-3 rounded-lg border border-border bg-bg-secondary py-16"
        >
          <Globe className="h-10 w-10 text-text-muted" />
          <p className="text-text-muted text-sm text-center max-w-md">
            No assets discovered yet. Create a target and run a scan to start discovering assets.
          </p>
        </div>
      </div>
    );
  }

  /* ── Main render ── */
  return (
    <div className="space-y-5 animate-fade-in">
      <PageHeader count={filtered.length} />

      {/* Controls: Search + Filters + Bulk Actions */}
      <div className="flex flex-col gap-3">
        <div className="flex items-center gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-text-muted" />
            <input
              data-testid="assets-search"
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
                setPage(0);
              }}
              placeholder="Search by hostname or IP..."
              className="w-full rounded-md border border-border bg-bg-tertiary py-2 pl-9 pr-3 text-sm text-text-primary placeholder:text-text-muted input-focus"
            />
          </div>
          <select
            data-testid="assets-type-filter"
            value={typeFilter}
            onChange={(e) => {
              setTypeFilter(e.target.value as TypeFilter);
              setPage(0);
            }}
            className="rounded-md border border-border bg-bg-tertiary px-3 py-2 text-sm text-text-primary input-focus"
          >
            <option value="all">All Types</option>
            <option value="domain">Domain</option>
            <option value="subdomain">Subdomain</option>
            <option value="ip">IP</option>
            <option value="cidr">CIDR</option>
            <option value="sensitive_file">Sensitive File</option>
            <option value="directory">Directory</option>
            <option value="error">Error Page</option>
            <option value="form">Form</option>
            <option value="upload">Upload</option>
            <option value="deadend">Dead End</option>
            <option value="undetermined">Undetermined</option>
          </select>
          <select
            data-testid="assets-class-filter"
            value={classFilter}
            onChange={(e) => {
              setClassFilter(e.target.value as ClassFilter);
              setPage(0);
            }}
            className="rounded-md border border-border bg-bg-tertiary px-3 py-2 text-sm text-text-primary input-focus"
          >
            <option value="all">All Scope</option>
            <option value="in_scope">In Scope</option>
            <option value="out_of_scope">Out of Scope</option>
            <option value="pending">Pending</option>
            <option value="associated">Associated</option>
            <option value="undetermined">Undetermined</option>
          </select>
        </div>

        {/* Bulk action bar — visible when items selected */}
        {selected.size > 0 && (
          <div
            data-testid="assets-bulk-bar"
            className="flex items-center gap-3 rounded-md border border-neon-blue/30 bg-neon-blue-glow px-4 py-2"
          >
            <span className="text-sm font-medium text-neon-blue">
              {selected.size} selected
            </span>
            <div className="ml-auto flex items-center gap-2">
              <button
                data-testid="bulk-set-in-scope"
                disabled={bulkLoading}
                onClick={() => handleBulkClassify("in_scope")}
                className="flex items-center gap-1.5 rounded-md border border-neon-green/30 bg-neon-green-glow px-3 py-1.5 text-xs font-medium text-neon-green transition-colors hover:bg-neon-green/20 disabled:opacity-50"
              >
                <ShieldCheck className="h-3.5 w-3.5" />
                Set In-scope
              </button>
              <button
                data-testid="bulk-set-out-scope"
                disabled={bulkLoading}
                onClick={() => handleBulkClassify("out_of_scope")}
                className="flex items-center gap-1.5 rounded-md border border-danger/30 bg-danger/5 px-3 py-1.5 text-xs font-medium text-danger transition-colors hover:bg-danger/20 disabled:opacity-50"
              >
                <ShieldOff className="h-3.5 w-3.5" />
                Set Out-of-scope
              </button>
              <button
                data-testid="bulk-clear-selection"
                onClick={() => setSelected(new Set())}
                className="rounded-md border border-border bg-bg-surface px-3 py-1.5 text-xs text-text-muted transition-colors hover:bg-bg-tertiary"
              >
                Clear
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Table */}
      <div data-testid="assets-table" className="overflow-x-auto rounded-lg border border-border">
        <table className="w-full text-left text-sm">
          <thead className="bg-bg-surface text-xs text-text-secondary">
            <tr>
              {/* Select-all checkbox */}
              <th className="w-10 px-2 py-3">
                <button
                  data-testid="select-all-checkbox"
                  onClick={toggleSelectAll}
                  className="rounded p-0.5 hover:bg-bg-tertiary transition-colors"
                  aria-label={allPageSelected ? "Deselect all" : "Select all"}
                >
                  {allPageSelected ? (
                    <CheckSquare className="h-4 w-4 text-neon-blue" />
                  ) : somePageSelected ? (
                    <MinusSquare className="h-4 w-4 text-neon-blue" />
                  ) : (
                    <Square className="h-4 w-4 text-text-muted" />
                  )}
                </button>
              </th>
              <SortHeader label="Type" field="asset_type" current={sortKey} dir={sortDir} onSort={toggleSort} />
              <SortHeader label="Hostname / IP" field="asset_value" current={sortKey} dir={sortDir} onSort={toggleSort} />
              <th className="px-4 py-3 font-medium text-xs">Scope</th>
              <SortHeader label="Ports" field="ports" current={sortKey} dir={sortDir} onSort={toggleSort} />
              <SortHeader label="Source Tool" field="source_tool" current={sortKey} dir={sortDir} onSort={toggleSort} />
              <SortHeader label="Discovered" field="created_at" current={sortKey} dir={sortDir} onSort={toggleSort} />
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {paged.length === 0 ? (
              <tr>
                <td colSpan={7} className="px-4 py-8 text-center text-text-muted">
                  No assets match the current filters.
                </td>
              </tr>
            ) : (
              paged.map((row) => {
                const ports = formatPorts(row.locations);

                return (
                  <tr
                    key={row.id}
                    data-testid={`asset-row-${row.id}`}
                    onClick={() => router.push(`/campaign/assets/${row.id}`)}
                    className={`cursor-pointer bg-bg-secondary transition-colors hover:bg-bg-tertiary ${
                      isSelected(row.id) ? "ring-1 ring-inset ring-neon-blue/30" : ""
                    }`}
                  >
                    <td className="px-2 py-2.5">
                      <button
                        data-testid={`asset-checkbox-${row.id}`}
                        onClick={(e) => { e.stopPropagation(); toggleSelect(row.id); }}
                        className="rounded p-0.5 hover:bg-bg-surface transition-colors"
                      >
                        {selected.has(row.id) ? (
                          <CheckSquare className="h-4 w-4 text-neon-blue" />
                        ) : (
                          <Square className="h-4 w-4 text-text-muted" />
                        )}
                      </button>
                    </td>
                    <td className="px-4 py-2.5">
                      <span className={`inline-block rounded border px-2 py-0.5 text-xs font-medium ${
                        TYPE_BADGE[row.asset_type] ?? TYPE_BADGE.url
                      }`}>
                        {row.asset_type}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 font-mono text-text-primary">{row.asset_value}</td>
                    <td className="px-4 py-2.5">
                      <span data-testid={`asset-scope-badge-${row.id}`}
                        className={`inline-block rounded border px-2 py-0.5 text-xs font-medium ${
                          CLASSIFICATION_BADGE[row.scope_classification ?? "pending"] ?? CLASSIFICATION_BADGE.undetermined
                        }`}>
                        {(row.scope_classification ?? "pending").replace(/_/g, " ")}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 font-mono text-xs text-text-secondary">{ports.display}</td>
                    <td className="px-4 py-2.5 font-mono text-xs text-text-secondary">
                      {row.source_tool ?? "—"}
                    </td>
                    <td className="px-4 py-2.5 font-mono text-xs text-text-muted">
                      {relativeTime(row.created_at)}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <div data-testid="assets-pagination" className="flex items-center justify-between text-xs text-text-muted">
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
    </div>
  );
}

/* ── Page Header (extracted for reuse across states) ── */

function PageHeader({ count }: { count: number }) {
  return (
    <div className="flex items-center justify-between">
      <div>
        <h1 className="flex items-center gap-2 text-2xl font-bold text-text-primary">
          <Globe className="h-5 w-5 text-neon-blue" />
          Assets
        </h1>
        <p className="mt-1 text-sm text-text-secondary">
          Discovered assets across all categories
        </p>
      </div>
      <span className="rounded-md border border-border bg-bg-surface px-3 py-1 font-mono text-sm text-text-primary">
        {count}
      </span>
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
      <button className="flex items-center gap-1" onClick={() => onSort(field)}>
        {label}
        <ArrowUpDown className={`h-3 w-3 ${active ? "text-neon-orange" : "text-text-muted"}`} />
        {active && (
          <span className="text-[10px] text-neon-orange">{dir === "asc" ? "\u2191" : "\u2193"}</span>
        )}
      </button>
    </th>
  );
}
