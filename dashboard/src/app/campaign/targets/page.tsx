"use client";

import { useEffect, useState, useMemo, useCallback } from "react";
import {
  Loader2,
  Search,
  ArrowUpDown,
  ChevronLeft,
  ChevronRight,
  Trash2,
  Eraser,
  MoreVertical,
} from "lucide-react";
import { api } from "@/lib/api";
import { useCampaignStore } from "@/stores/campaign";
import type { TargetWithStats } from "@/types/schema";

type SortKey = "company_name" | "base_domain" | "status" | "asset_count" | "vuln_count" | "last_activity";
type SortDir = "asc" | "desc";

const PAGE_SIZE = 25;

const STATUS_BADGE: Record<string, string> = {
  running: "bg-neon-green-glow text-neon-green border-neon-green/20",
  queued: "bg-neon-blue-glow text-neon-blue border-neon-blue/20",
  paused: "bg-neon-orange-glow text-neon-orange border-neon-orange/20",
  completed: "bg-bg-surface text-text-muted border-border",
  failed: "bg-danger/15 text-danger border-danger/25",
  idle: "bg-bg-surface text-text-muted border-border",
};

export default function TargetsPage() {
  const { activeTarget, setActiveTarget } = useCampaignStore();
  const [data, setData] = useState<TargetWithStats[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>("last_activity");
  const [sortDir, setSortDir] = useState<SortDir>("desc");
  const [page, setPage] = useState(0);

  const [eraseTarget, setEraseTarget] = useState<TargetWithStats | null>(null);
  const [erasing, setErasing] = useState(false);

  const [deleteTargetState, setDeleteTargetState] = useState<TargetWithStats | null>(null);
  const [deleteConfirm, setDeleteConfirm] = useState("");
  const [deleting, setDeleting] = useState(false);

  const [menuOpen, setMenuOpen] = useState<number | null>(null);

  const fetchTargets = useCallback(async () => {
    try {
      const res = await api.getTargets();
      setData(res.targets);
    } catch {
      // toast shown by api.request()
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchTargets();
  }, [fetchTargets]);

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
      rows = rows.filter(
        (r) =>
          r.company_name.toLowerCase().includes(q) ||
          r.base_domain.toLowerCase().includes(q),
      );
    }
    rows = [...rows].sort((a, b) => {
      const av = a[sortKey] ?? "";
      const bv = b[sortKey] ?? "";
      if (typeof av === "number" && typeof bv === "number") {
        return sortDir === "asc" ? av - bv : bv - av;
      }
      return sortDir === "asc"
        ? String(av).localeCompare(String(bv))
        : String(bv).localeCompare(String(av));
    });
    return rows;
  }, [data, search, sortKey, sortDir]);

  const totalPages = Math.ceil(filtered.length / PAGE_SIZE);
  const paged = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  const handleErase = async () => {
    if (!eraseTarget) return;
    setErasing(true);
    try {
      await api.cleanSlate(eraseTarget.id);
      await fetchTargets();
    } catch {
      // toast shown by api.request()
    } finally {
      setErasing(false);
      setEraseTarget(null);
    }
  };

  const handleDelete = async () => {
    if (!deleteTargetState || deleteConfirm !== deleteTargetState.base_domain) return;
    setDeleting(true);
    try {
      await api.deleteTarget(deleteTargetState.id);
      if (activeTarget?.id === deleteTargetState.id) {
        setActiveTarget(null);
      }
      await fetchTargets();
    } catch {
      // toast shown by api.request()
    } finally {
      setDeleting(false);
      setDeleteTargetState(null);
      setDeleteConfirm("");
    }
  };

  const SortHeader = ({ label, field }: { label: string; field: SortKey }) => (
    <button
      onClick={() => toggleSort(field)}
      className="inline-flex items-center gap-1 text-xs font-medium uppercase tracking-wider text-text-muted hover:text-text-primary"
    >
      {label}
      <ArrowUpDown className="h-3 w-3" />
    </button>
  );

  if (loading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <Loader2 className="h-5 w-5 animate-spin text-accent" />
      </div>
    );
  }

  return (
    <div className="space-y-4 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <h1 className="text-lg font-semibold text-text-primary">
            Target Management
          </h1>
          <span className="rounded-full bg-bg-surface px-2 py-0.5 text-xs font-mono text-text-muted border border-border">
            {data.length}
          </span>
        </div>
        <div className="relative">
          <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-text-muted" />
          <input
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(0);
            }}
            placeholder="Search targets..."
            data-testid="target-search-input"
            className="h-8 w-56 rounded-md border border-border bg-bg-secondary pl-9 pr-3 text-xs text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none"
          />
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto rounded-lg border border-border bg-bg-secondary">
        <table data-testid="targets-table" className="w-full text-sm">
          <thead>
            <tr className="border-b border-border">
              <th className="px-4 py-3 text-left"><SortHeader label="Company" field="company_name" /></th>
              <th className="px-4 py-3 text-left"><SortHeader label="Domain" field="base_domain" /></th>
              <th className="px-4 py-3 text-left"><SortHeader label="Status" field="status" /></th>
              <th className="px-4 py-3 text-right"><SortHeader label="Assets" field="asset_count" /></th>
              <th className="px-4 py-3 text-right"><SortHeader label="Vulns" field="vuln_count" /></th>
              <th className="px-4 py-3 text-left"><SortHeader label="Last Activity" field="last_activity" /></th>
              <th className="px-4 py-3 text-right">
                <span className="text-xs font-medium uppercase tracking-wider text-text-muted">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {paged.map((t) => (
              <tr key={t.id} data-testid={`target-row-${t.id}`} className="border-b border-border/50 last:border-0 hover:bg-bg-tertiary/50">
                <td className="px-4 py-3 font-medium text-text-primary">{t.company_name}</td>
                <td className="px-4 py-3 font-mono text-xs text-text-secondary">{t.base_domain}</td>
                <td className="px-4 py-3">
                  <span className={`inline-block rounded-full border px-2 py-0.5 text-xs font-medium ${STATUS_BADGE[t.status] ?? STATUS_BADGE.idle}`}>
                    {t.status}
                  </span>
                </td>
                <td className="px-4 py-3 text-right font-mono text-xs text-text-secondary">{t.asset_count.toLocaleString()}</td>
                <td className="px-4 py-3 text-right font-mono text-xs text-text-secondary">{t.vuln_count.toLocaleString()}</td>
                <td className="px-4 py-3 text-xs text-text-muted">
                  {t.last_activity ? new Date(t.last_activity).toLocaleString() : "\u2014"}
                </td>
                <td className="px-4 py-3 text-right">
                  <div className="relative inline-block">
                    <button
                      onClick={() => setMenuOpen(menuOpen === t.id ? null : t.id)}
                      className="rounded p-1 text-text-muted hover:bg-bg-surface hover:text-text-primary"
                    >
                      <MoreVertical className="h-4 w-4" />
                    </button>
                    {menuOpen === t.id && (
                      <div className="absolute right-0 top-full z-20 mt-1 w-44 rounded-md border border-border bg-bg-secondary shadow-lg">
                        <button
                          onClick={() => { setEraseTarget(t); setMenuOpen(null); }}
                          className="flex w-full items-center gap-2 px-3 py-2 text-xs text-text-secondary hover:bg-bg-tertiary hover:text-neon-orange"
                        >
                          <Eraser className="h-3.5 w-3.5" />
                          Erase Data
                        </button>
                        <button
                          data-testid={`target-delete-btn-${t.id}`}
                          onClick={() => { setDeleteTargetState(t); setMenuOpen(null); }}
                          className="flex w-full items-center gap-2 px-3 py-2 text-xs text-text-secondary hover:bg-bg-tertiary hover:text-danger"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                          Delete Target
                        </button>
                      </div>
                    )}
                  </div>
                </td>
              </tr>
            ))}
            {paged.length === 0 && (
              <tr>
                <td colSpan={7} className="px-4 py-8 text-center text-sm text-text-muted">
                  {search ? "No targets match your search." : "No targets yet."}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between text-xs text-text-muted">
          <span>
            {page * PAGE_SIZE + 1}&ndash;{Math.min((page + 1) * PAGE_SIZE, filtered.length)} of {filtered.length}
          </span>
          <div className="flex gap-1">
            <button disabled={page === 0} onClick={() => setPage((p) => p - 1)} className="rounded p-1 hover:bg-bg-surface disabled:opacity-30">
              <ChevronLeft className="h-4 w-4" />
            </button>
            <button disabled={page >= totalPages - 1} onClick={() => setPage((p) => p + 1)} className="rounded p-1 hover:bg-bg-surface disabled:opacity-30">
              <ChevronRight className="h-4 w-4" />
            </button>
          </div>
        </div>
      )}

      {/* Erase Confirmation Dialog */}
      {eraseTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={() => !erasing && setEraseTarget(null)}>
          <div className="w-96 rounded-lg border border-neon-orange/30 bg-bg-secondary p-5 shadow-xl" onClick={(e) => e.stopPropagation()}>
            <h3 className="text-sm font-semibold text-text-primary">Erase Target Data</h3>
            <p className="mt-2 text-xs text-text-muted">
              This will permanently erase all discovered assets, vulnerabilities, jobs, and alerts for{" "}
              <span className="font-semibold text-text-primary">{eraseTarget.company_name}</span>{" "}
              ({eraseTarget.base_domain}). The target and bounty submissions are preserved. This cannot be undone.
            </p>
            <div className="mt-4 flex justify-end gap-2">
              <button disabled={erasing} onClick={() => setEraseTarget(null)} className="rounded-md border border-border px-3 py-1.5 text-xs text-text-secondary hover:bg-bg-tertiary">
                Cancel
              </button>
              <button disabled={erasing} onClick={handleErase} className="rounded-md bg-neon-orange/20 px-3 py-1.5 text-xs font-medium text-neon-orange border border-neon-orange/30 hover:bg-neon-orange/30 disabled:opacity-50">
                {erasing ? "Erasing..." : "Erase Data"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Delete Confirmation Dialog */}
      {deleteTargetState && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={() => !deleting && (setDeleteTargetState(null), setDeleteConfirm(""))}>
          <div className="w-96 rounded-lg border border-danger/30 bg-bg-secondary p-5 shadow-xl" onClick={(e) => e.stopPropagation()}>
            <h3 className="text-sm font-semibold text-danger">Delete Target Permanently</h3>
            <p className="mt-2 text-xs text-text-muted">
              This will permanently delete{" "}
              <span className="font-semibold text-text-primary">{deleteTargetState.company_name}</span>{" "}
              and ALL associated data including bounty submissions, config, and reports. Any running workers will be killed.
            </p>
            <p className="mt-3 text-xs text-text-muted">
              Type <span className="font-mono font-semibold text-danger">{deleteTargetState.base_domain}</span> to confirm:
            </p>
            <input
              value={deleteConfirm}
              onChange={(e) => setDeleteConfirm(e.target.value)}
              placeholder={deleteTargetState.base_domain}
              className="mt-2 w-full rounded-md border border-border bg-bg-primary px-3 py-1.5 font-mono text-xs text-text-primary placeholder:text-text-muted/40 focus:border-danger focus:outline-none"
            />
            <div className="mt-4 flex justify-end gap-2">
              <button disabled={deleting} onClick={() => { setDeleteTargetState(null); setDeleteConfirm(""); }} className="rounded-md border border-border px-3 py-1.5 text-xs text-text-secondary hover:bg-bg-tertiary">
                Cancel
              </button>
              <button
                disabled={deleting || deleteConfirm !== deleteTargetState.base_domain}
                onClick={handleDelete}
                className="rounded-md bg-danger/20 px-3 py-1.5 text-xs font-medium text-danger border border-danger/30 hover:bg-danger/30 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {deleting ? "Deleting..." : "Delete Target"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
