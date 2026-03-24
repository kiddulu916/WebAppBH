"use client";

import { useEffect, useState, useMemo, useCallback } from "react";
import Link from "next/link";
import {
  Server,
  ShieldAlert,
  Cloud,
  Bell,
  Cpu,
  ChevronLeft,
  ChevronRight,
  ChevronDown,
  ChevronUp,
  Download,
  Search,
  Database,
  X,
} from "lucide-react";
import { useCampaignStore } from "@/stores/campaign";
import { api } from "@/lib/api";
import type { VulnSeverity } from "@/types/schema";

/* ------------------------------------------------------------------ */
/* Tab definitions                                                     */
/* ------------------------------------------------------------------ */

const TABS = [
  { key: "assets", label: "Assets", icon: Server },
  { key: "vulnerabilities", label: "Vulnerabilities", icon: ShieldAlert },
  { key: "cloud", label: "Cloud Assets", icon: Cloud },
  { key: "alerts", label: "Alerts", icon: Bell },
  { key: "jobs", label: "Jobs", icon: Cpu },
] as const;

type TabKey = (typeof TABS)[number]["key"];

/* ------------------------------------------------------------------ */
/* Vuln row type (from API)                                            */
/* ------------------------------------------------------------------ */

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

/* ------------------------------------------------------------------ */
/* Sorting                                                             */
/* ------------------------------------------------------------------ */

type SortDir = "asc" | "desc" | null;

interface SortState {
  column: string;
  dir: SortDir;
}

function sortData<T extends Record<string, unknown>>(
  data: T[],
  sort: SortState,
): T[] {
  if (!sort.dir || !sort.column) return data;
  const col = sort.column;
  const dir = sort.dir === "asc" ? 1 : -1;
  return [...data].sort((a, b) => {
    const av = a[col];
    const bv = b[col];
    if (av == null && bv == null) return 0;
    if (av == null) return 1;
    if (bv == null) return -1;
    if (typeof av === "number" && typeof bv === "number")
      return (av - bv) * dir;
    return String(av).localeCompare(String(bv)) * dir;
  });
}

/* ------------------------------------------------------------------ */
/* Pagination                                                          */
/* ------------------------------------------------------------------ */

const PAGE_SIZE = 25;

/* ------------------------------------------------------------------ */
/* Export helpers                                                       */
/* ------------------------------------------------------------------ */

function downloadJSON(data: unknown[], filename: string) {
  const blob = new Blob([JSON.stringify(data, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function downloadCSV(data: Record<string, unknown>[], filename: string) {
  if (data.length === 0) return;
  const headers = Object.keys(data[0]);
  const rows = data.map((row) =>
    headers
      .map((h) => {
        const val = row[h];
        const str = val == null ? "" : String(val);
        // Escape quotes and wrap in quotes if contains comma/newline
        if (str.includes(",") || str.includes("\n") || str.includes('"')) {
          return `"${str.replace(/"/g, '""')}"`;
        }
        return str;
      })
      .join(","),
  );
  const csv = [headers.join(","), ...rows].join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

/* ------------------------------------------------------------------ */
/* Column definitions per tab                                          */
/* ------------------------------------------------------------------ */

interface ColDef {
  key: string;
  label: string;
  mono?: boolean;
  render?: (val: unknown, row: Record<string, unknown>) => React.ReactNode;
}

const SEV_COLORS: Record<string, string> = {
  critical: "bg-sev-critical/20 text-sev-critical",
  high: "bg-sev-high/20 text-sev-high",
  medium: "bg-sev-medium/20 text-sev-medium",
  low: "bg-sev-low/20 text-sev-low",
  info: "bg-bg-surface text-text-muted",
};

const PROVIDER_COLORS: Record<string, string> = {
  AWS: "bg-warning/20 text-warning",
  Azure: "bg-neon-blue/10 text-neon-blue",
  GCP: "bg-danger/20 text-danger",
  Other: "bg-bg-surface text-text-muted",
};

const STATUS_COLORS: Record<string, string> = {
  RUNNING: "bg-neon-orange/10 text-neon-orange",
  COMPLETED: "bg-neon-green/10 text-neon-green",
  FAILED: "bg-danger/20 text-danger",
  QUEUED: "bg-bg-surface text-text-muted",
  PAUSED: "bg-warning/20 text-warning",
  STOPPED: "bg-bg-surface text-text-secondary",
};

function timestampRenderer(val: unknown) {
  if (!val) return <span className="text-text-muted">--</span>;
  return (
    <span className="font-mono text-xs text-text-secondary">
      {new Date(String(val)).toLocaleString()}
    </span>
  );
}

function boolRenderer(val: unknown) {
  return val ? (
    <span className="font-semibold text-danger">Yes</span>
  ) : (
    <span className="text-neon-green">No</span>
  );
}

const COLUMNS: Record<TabKey, ColDef[]> = {
  assets: [
    { key: "id", label: "ID", mono: true },
    {
      key: "asset_type",
      label: "Type",
      render: (v) => (
        <span className="rounded bg-neon-orange/10 px-2 py-0.5 text-xs text-neon-orange">
          {String(v)}
        </span>
      ),
    },
    { key: "asset_value", label: "Value", mono: true },
    { key: "source_tool", label: "Source", mono: true },
    { key: "created_at", label: "Discovered", render: timestampRenderer },
  ],
  vulnerabilities: [
    { key: "id", label: "ID", mono: true },
    {
      key: "severity",
      label: "Severity",
      render: (v) => (
        <span
          className={`rounded px-2 py-0.5 text-xs font-medium ${SEV_COLORS[String(v)] ?? ""}`}
        >
          {String(v).toUpperCase()}
        </span>
      ),
    },
    { key: "title", label: "Title" },
    { key: "asset_value", label: "Asset", mono: true },
    { key: "source_tool", label: "Source", mono: true },
    { key: "created_at", label: "Found", render: timestampRenderer },
  ],
  cloud: [
    { key: "id", label: "ID", mono: true },
    {
      key: "provider",
      label: "Provider",
      render: (v) => (
        <span
          className={`rounded px-2 py-0.5 text-xs font-medium ${PROVIDER_COLORS[String(v)] ?? PROVIDER_COLORS.Other}`}
        >
          {String(v)}
        </span>
      ),
    },
    { key: "asset_type", label: "Type", mono: true },
    {
      key: "url",
      label: "URL",
      mono: true,
      render: (v) =>
        v ? (
          <span
            className="inline-block max-w-xs truncate font-mono text-xs"
            title={String(v)}
          >
            {String(v)}
          </span>
        ) : (
          <span className="text-text-muted">--</span>
        ),
    },
    { key: "is_public", label: "Public", render: boolRenderer },
    { key: "created_at", label: "Found", render: timestampRenderer },
  ],
  alerts: [
    { key: "id", label: "ID", mono: true },
    { key: "alert_type", label: "Type", mono: true },
    { key: "message", label: "Message" },
    {
      key: "is_read",
      label: "Read",
      render: (v) =>
        v ? (
          <span className="text-text-muted">Yes</span>
        ) : (
          <span className="font-semibold text-neon-orange">New</span>
        ),
    },
    { key: "vulnerability_id", label: "Vuln ID", mono: true },
    { key: "created_at", label: "Time", render: timestampRenderer },
  ],
  jobs: [
    { key: "id", label: "ID", mono: true },
    { key: "container_name", label: "Container", mono: true },
    { key: "current_phase", label: "Phase", mono: true },
    {
      key: "status",
      label: "Status",
      render: (v) => (
        <span
          className={`rounded px-2 py-0.5 text-xs font-medium ${STATUS_COLORS[String(v)] ?? ""}`}
        >
          {String(v)}
        </span>
      ),
    },
    { key: "last_tool_executed", label: "Last Tool", mono: true },
    { key: "last_seen", label: "Last Seen", render: timestampRenderer },
  ],
};

/* ------------------------------------------------------------------ */
/* Filter definitions per tab                                          */
/* ------------------------------------------------------------------ */

interface FilterDef {
  key: string;
  label: string;
  type: "select" | "search";
  options?: string[];
}

const FILTERS: Record<TabKey, FilterDef[]> = {
  assets: [
    {
      key: "asset_type",
      label: "Type",
      type: "select",
      options: ["all", "subdomain", "ip", "cidr", "url"],
    },
    {
      key: "source_tool",
      label: "Source",
      type: "select",
      options: [], // populated dynamically
    },
    { key: "search", label: "Search", type: "search" },
  ],
  vulnerabilities: [
    {
      key: "severity",
      label: "Severity",
      type: "select",
      options: ["all", "critical", "high", "medium", "low", "info"],
    },
    { key: "search", label: "Search", type: "search" },
  ],
  cloud: [
    {
      key: "provider",
      label: "Provider",
      type: "select",
      options: ["all", "AWS", "Azure", "GCP", "Other"],
    },
    { key: "search", label: "Search", type: "search" },
  ],
  alerts: [
    {
      key: "is_read",
      label: "Status",
      type: "select",
      options: ["all", "unread", "read"],
    },
    { key: "search", label: "Search", type: "search" },
  ],
  jobs: [
    {
      key: "status",
      label: "Status",
      type: "select",
      options: ["all", "RUNNING", "COMPLETED", "FAILED", "QUEUED", "PAUSED", "STOPPED"],
    },
    { key: "search", label: "Search", type: "search" },
  ],
};

/* ------------------------------------------------------------------ */
/* Sort header component                                               */
/* ------------------------------------------------------------------ */

function SortHeader({
  col,
  sort,
  onSort,
}: {
  col: ColDef;
  sort: SortState;
  onSort: (column: string) => void;
}) {
  const active = sort.column === col.key;
  return (
    <th
      className="cursor-pointer select-none px-3 py-2 text-left text-[11px] font-semibold uppercase tracking-wider text-text-muted transition-colors hover:text-text-secondary"
      onClick={() => onSort(col.key)}
    >
      <span className="inline-flex items-center gap-1">
        {col.label}
        {active && sort.dir === "asc" && (
          <ChevronUp className="h-3 w-3 text-neon-orange" />
        )}
        {active && sort.dir === "desc" && (
          <ChevronDown className="h-3 w-3 text-neon-orange" />
        )}
      </span>
    </th>
  );
}

/* ------------------------------------------------------------------ */
/* Main page component                                                 */
/* ------------------------------------------------------------------ */

export default function ExplorerPage() {
  const { activeTarget } = useCampaignStore();

  const [activeTab, setActiveTab] = useState<TabKey>("assets");
  const [rawData, setRawData] = useState<Record<string, unknown>[]>([]);
  const [loading, setLoading] = useState(false);
  const [filterValues, setFilterValues] = useState<Record<string, string>>({});
  const [sort, setSort] = useState<SortState>({ column: "id", dir: "desc" });
  const [page, setPage] = useState(0);
  const [expandedRow, setExpandedRow] = useState<number | null>(null);

  /* ---- Dynamic source_tool options for assets ---- */
  const sourceToolOptions = useMemo(() => {
    if (activeTab !== "assets") return [];
    const tools = new Set<string>();
    for (const row of rawData) {
      if (row.source_tool) tools.add(String(row.source_tool));
    }
    return ["all", ...Array.from(tools).sort()];
  }, [rawData, activeTab]);

  /* ---- Fetch data when tab or target changes ---- */
  useEffect(() => {
    if (!activeTarget) return;
    setLoading(true);
    setExpandedRow(null);
    setPage(0);

    let cancelled = false;

    async function fetchData() {
      try {
        let result: Record<string, unknown>[] = [];

        switch (activeTab) {
          case "assets": {
            const res = await api.getAssets(activeTarget!.id);
            result = res.assets as unknown as Record<string, unknown>[];
            break;
          }
          case "vulnerabilities": {
            const res = await api.getVulnerabilities(activeTarget!.id);
            result = res.vulnerabilities as unknown as Record<string, unknown>[];
            break;
          }
          case "cloud": {
            const res = await api.getCloudAssets(activeTarget!.id);
            result = res.cloud_assets as unknown as Record<string, unknown>[];
            break;
          }
          case "alerts": {
            const res = await api.getAlerts(activeTarget!.id);
            result = res.alerts as unknown as Record<string, unknown>[];
            break;
          }
          case "jobs": {
            const res = await api.getStatus(activeTarget!.id);
            result = res.jobs as unknown as Record<string, unknown>[];
            break;
          }
        }

        if (!cancelled) setRawData(result);
      } catch {
        // toast shown by api.request()
        if (!cancelled) setRawData([]);
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    fetchData();
    return () => {
      cancelled = true;
    };
  }, [activeTab, activeTarget]);

  /* ---- Filter logic ---- */
  const filteredData = useMemo(() => {
    let data = rawData;

    for (const [key, value] of Object.entries(filterValues)) {
      if (!value || value === "all") continue;

      if (key === "search") {
        const q = value.toLowerCase();
        data = data.filter((row) =>
          Object.values(row).some((v) =>
            String(v ?? "")
              .toLowerCase()
              .includes(q),
          ),
        );
      } else if (key === "is_read") {
        data = data.filter((row) =>
          value === "unread" ? !row.is_read : row.is_read,
        );
      } else {
        data = data.filter(
          (row) =>
            String(row[key] ?? "").toLowerCase() === value.toLowerCase(),
        );
      }
    }

    return data;
  }, [rawData, filterValues]);

  /* ---- Sort ---- */
  const sortedData = useMemo(
    () => sortData(filteredData, sort),
    [filteredData, sort],
  );

  /* ---- Pagination ---- */
  const totalPages = Math.max(1, Math.ceil(sortedData.length / PAGE_SIZE));
  const pagedData = useMemo(
    () => sortedData.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE),
    [sortedData, page],
  );

  /* ---- Handlers ---- */
  const handleSort = useCallback(
    (column: string) => {
      setSort((prev) => {
        if (prev.column === column) {
          if (prev.dir === "asc") return { column, dir: "desc" };
          if (prev.dir === "desc") return { column: "id", dir: "desc" };
          return { column, dir: "asc" };
        }
        return { column, dir: "asc" };
      });
    },
    [],
  );

  const handleTabChange = useCallback((tab: TabKey) => {
    setActiveTab(tab);
    setFilterValues({});
    setSort({ column: "id", dir: "desc" });
    setExpandedRow(null);
  }, []);

  const handleFilterChange = useCallback((key: string, value: string) => {
    setFilterValues((prev) => ({ ...prev, [key]: value }));
    setPage(0);
  }, []);

  /* ---- Current columns and filters ---- */
  const columns = COLUMNS[activeTab];
  const filterDefs = FILTERS[activeTab];

  // Inject dynamic source_tool options
  const resolvedFilters = useMemo(() => {
    if (activeTab === "assets") {
      return filterDefs.map((f) =>
        f.key === "source_tool"
          ? { ...f, options: sourceToolOptions }
          : f,
      );
    }
    return filterDefs;
  }, [filterDefs, sourceToolOptions, activeTab]);

  /* ---- No campaign state ---- */
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
    <div className="space-y-5 animate-fade-in">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-text-primary">Data Explorer</h1>
        <p className="mt-1 text-sm text-text-secondary">
          Full database access for{" "}
          <span className="font-mono text-neon-orange">
            {activeTarget.base_domain}
          </span>
        </p>
      </div>

      {/* Pill tabs */}
      <div className="flex gap-1.5">
        {TABS.map(({ key, label, icon: Icon }) => (
          <button
            key={key}
            onClick={() => handleTabChange(key)}
            className={`inline-flex items-center gap-1.5 rounded-full px-3.5 py-1.5 text-xs font-medium transition-all ${
              activeTab === key
                ? "bg-neon-orange/15 text-neon-orange glow-orange"
                : "bg-bg-surface text-text-muted hover:bg-bg-tertiary hover:text-text-secondary"
            }`}
          >
            <Icon className="h-3.5 w-3.5" />
            {label}
          </button>
        ))}
      </div>

      {/* Filter bar */}
      <div className="flex flex-wrap items-center gap-2 rounded-lg border border-border bg-bg-secondary px-3 py-2">
        {resolvedFilters.map((f) => {
          if (f.type === "select" && f.options && f.options.length > 0) {
            return (
              <select
                key={f.key}
                value={filterValues[f.key] ?? "all"}
                onChange={(e) => handleFilterChange(f.key, e.target.value)}
                className="rounded border border-border bg-bg-tertiary px-2.5 py-1.5 font-mono text-xs text-text-primary outline-none transition-colors focus:border-neon-orange"
              >
                {f.options.map((opt) => (
                  <option key={opt} value={opt}>
                    {f.label}: {opt === "all" ? "All" : opt}
                  </option>
                ))}
              </select>
            );
          }
          if (f.type === "search") {
            return (
              <div key={f.key} className="relative flex-1 min-w-[200px]">
                <Search className="absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-text-muted" />
                <input
                  type="text"
                  placeholder="Search across all fields..."
                  value={filterValues[f.key] ?? ""}
                  onChange={(e) => handleFilterChange(f.key, e.target.value)}
                  className="w-full rounded border border-border bg-bg-tertiary py-1.5 pl-7 pr-7 font-mono text-xs text-text-primary outline-none transition-colors placeholder:text-text-muted focus:border-neon-orange"
                />
                {filterValues[f.key] && (
                  <button
                    onClick={() => handleFilterChange(f.key, "")}
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-primary"
                  >
                    <X className="h-3 w-3" />
                  </button>
                )}
              </div>
            );
          }
          return null;
        })}
        <span className="ml-auto text-[11px] text-text-muted">
          <span className="font-mono text-text-secondary">
            {filteredData.length}
          </span>{" "}
          records
        </span>
      </div>

      {/* Table */}
      <div className="overflow-x-auto rounded-lg border border-border bg-bg-secondary">
        {loading ? (
          <div className="flex h-40 items-center justify-center">
            <div className="h-5 w-5 animate-spin rounded-full border-2 border-neon-orange border-t-transparent" />
          </div>
        ) : pagedData.length === 0 ? (
          <div className="flex h-40 flex-col items-center justify-center gap-2">
            <Database className="h-8 w-8 text-text-muted" />
            <p className="text-sm text-text-muted">No data found</p>
          </div>
        ) : (
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border bg-bg-tertiary">
                {columns.map((col) => (
                  <SortHeader
                    key={col.key}
                    col={col}
                    sort={sort}
                    onSort={handleSort}
                  />
                ))}
              </tr>
            </thead>
            <tbody>
              {pagedData.map((row, idx) => {
                const rowId = Number(row.id);
                const isExpanded = expandedRow === rowId;

                return (
                  <TableRow
                    key={`${rowId}-${idx}`}
                    row={row}
                    rowId={rowId}
                    columns={columns}
                    isExpanded={isExpanded}
                    onToggle={() =>
                      setExpandedRow(isExpanded ? null : rowId)
                    }
                  />
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      {/* Pagination + Export */}
      <div className="flex items-center justify-between">
        {/* Pagination */}
        <div className="flex items-center gap-1.5">
          <button
            onClick={() => setPage((p) => Math.max(0, p - 1))}
            disabled={page === 0}
            className="rounded border border-border bg-bg-surface p-1.5 text-text-muted transition-colors hover:border-neon-orange/40 hover:text-text-primary disabled:opacity-30 disabled:hover:border-border disabled:hover:text-text-muted"
          >
            <ChevronLeft className="h-3.5 w-3.5" />
          </button>
          {Array.from({ length: Math.min(totalPages, 7) }, (_, i) => {
            let pageNum: number;
            if (totalPages <= 7) {
              pageNum = i;
            } else if (page < 4) {
              pageNum = i;
            } else if (page > totalPages - 5) {
              pageNum = totalPages - 7 + i;
            } else {
              pageNum = page - 3 + i;
            }
            return (
              <button
                key={pageNum}
                onClick={() => setPage(pageNum)}
                className={`rounded px-2.5 py-1 font-mono text-xs transition-colors ${
                  page === pageNum
                    ? "bg-neon-orange/15 text-neon-orange"
                    : "text-text-muted hover:bg-bg-surface hover:text-text-primary"
                }`}
              >
                {pageNum + 1}
              </button>
            );
          })}
          <button
            onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
            disabled={page >= totalPages - 1}
            className="rounded border border-border bg-bg-surface p-1.5 text-text-muted transition-colors hover:border-neon-orange/40 hover:text-text-primary disabled:opacity-30 disabled:hover:border-border disabled:hover:text-text-muted"
          >
            <ChevronRight className="h-3.5 w-3.5" />
          </button>
          <span className="ml-2 text-[11px] text-text-muted">
            Page{" "}
            <span className="font-mono text-text-secondary">{page + 1}</span>{" "}
            of{" "}
            <span className="font-mono text-text-secondary">{totalPages}</span>
          </span>
        </div>

        {/* Export */}
        <div className="flex items-center gap-2">
          <button
            onClick={() =>
              downloadCSV(
                filteredData as Record<string, unknown>[],
                `${activeTab}-${activeTarget.base_domain}.csv`,
              )
            }
            disabled={filteredData.length === 0}
            className="inline-flex items-center gap-1.5 rounded border border-border bg-bg-surface px-3 py-1.5 text-xs text-text-secondary transition-colors hover:border-neon-blue/40 hover:text-neon-blue disabled:opacity-30"
          >
            <Download className="h-3 w-3" />
            CSV
          </button>
          <button
            onClick={() =>
              downloadJSON(
                filteredData,
                `${activeTab}-${activeTarget.base_domain}.json`,
              )
            }
            disabled={filteredData.length === 0}
            className="inline-flex items-center gap-1.5 rounded border border-border bg-bg-surface px-3 py-1.5 text-xs text-text-secondary transition-colors hover:border-neon-blue/40 hover:text-neon-blue disabled:opacity-30"
          >
            <Download className="h-3 w-3" />
            JSON
          </button>
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Table row with expand                                               */
/* ------------------------------------------------------------------ */

function TableRow({
  row,
  rowId,
  columns,
  isExpanded,
  onToggle,
}: {
  row: Record<string, unknown>;
  rowId: number;
  columns: ColDef[];
  isExpanded: boolean;
  onToggle: () => void;
}) {
  return (
    <>
      <tr
        onClick={onToggle}
        className={`cursor-pointer border-b border-border transition-colors ${
          isExpanded
            ? "border-l-2 border-l-neon-orange bg-bg-tertiary"
            : "hover:border-l-2 hover:border-l-neon-orange/50 hover:bg-bg-tertiary/50"
        }`}
      >
        {columns.map((col) => {
          const val = row[col.key];
          return (
            <td
              key={col.key}
              className={`px-3 py-2 ${col.mono ? "font-mono" : ""} text-text-primary`}
            >
              {col.render
                ? col.render(val, row)
                : val != null
                  ? String(val)
                  : <span className="text-text-muted">--</span>}
            </td>
          );
        })}
      </tr>
      {isExpanded && (
        <tr className="border-b border-border">
          <td colSpan={columns.length} className="p-0">
            <div className="border-l-2 border-l-neon-orange bg-bg-void/50 p-4 animate-slide-up">
              <div className="mb-2 flex items-center justify-between">
                <span className="section-label">Full Record</span>
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    onToggle();
                  }}
                  className="text-[10px] text-text-muted hover:text-text-primary"
                >
                  Close
                </button>
              </div>
              <pre className="overflow-x-auto rounded bg-bg-tertiary p-3 font-mono text-[11px] leading-relaxed text-text-code">
                {JSON.stringify(row, null, 2)}
              </pre>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}
