"use client";

import { useState, useMemo } from "react";
import Link from "next/link";
import {
  useReactTable,
  getCoreRowModel,
  getFilteredRowModel,
  getSortedRowModel,
  flexRender,
  createColumnHelper,
} from "@tanstack/react-table";
import type { Finding } from "@/types/schema";

interface FindingsTableProps {
  findings: Finding[];
  campaignId: string;
}

const columnHelper = createColumnHelper<Finding>();

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-sev-critical/20 text-sev-critical",
  high: "bg-sev-high/20 text-sev-high",
  medium: "bg-sev-medium/20 text-sev-medium",
  low: "bg-sev-low/20 text-sev-low",
  info: "bg-bg-surface text-text-muted",
};

export default function FindingsTable({ findings, campaignId }: FindingsTableProps) {
  const [severityFilter, setSeverityFilter] = useState<string[]>([]);
  const [workerFilter, setWorkerFilter] = useState<string[]>([]);
  const [confirmedOnly, setConfirmedOnly] = useState(false);
  const [hideFalsePositives, setHideFalsePositives] = useState(true);
  const [sectionFilter, setSectionFilter] = useState("");

  const columns = useMemo(
    () => [
      columnHelper.accessor("severity", {
        header: "Severity",
        cell: (info) => (
          <span
            className={`px-2 py-0.5 rounded text-xs font-medium ${
              SEVERITY_COLORS[info.getValue()] || SEVERITY_COLORS.info
            }`}
          >
            {info.getValue()}
          </span>
        ),
      }),
      columnHelper.accessor("title", {
        header: "Title",
        cell: (info) => (
          <Link
            href={`/campaign/${campaignId}/findings/${info.row.original.id}`}
            className="text-accent-primary hover:underline"
          >
            {info.getValue()}
          </Link>
        ),
      }),
      columnHelper.accessor("target_domain", {
        header: "Target",
        cell: (info) => info.getValue() || info.row.original.target_id,
      }),
      columnHelper.accessor("worker_type", {
        header: "Worker",
        cell: (info) => info.getValue() || "—",
      }),
      columnHelper.accessor("stage_name", {
        header: "Stage",
        cell: (info) => info.getValue() || "—",
      }),
      columnHelper.accessor("section_id", {
        header: "Section ID",
        cell: (info) => info.getValue() || "—",
      }),
      columnHelper.accessor("source_tool", {
        header: "Tool",
        cell: (info) => info.getValue() || "—",
      }),
      columnHelper.accessor("confirmed", {
        header: "Confirmed",
        cell: (info) => (info.getValue() ? "✓" : "—"),
      }),
      columnHelper.accessor("false_positive", {
        header: "FP",
        cell: (info) => (info.getValue() ? "✗" : "—"),
      }),
    ],
    [campaignId],
  );

  const filteredFindings = useMemo(() => {
    let result = findings;

    if (severityFilter.length > 0) {
      result = result.filter((f) => severityFilter.includes(f.severity));
    }

    if (workerFilter.length > 0) {
      result = result.filter((f) => f.worker_type && workerFilter.includes(f.worker_type));
    }

    if (confirmedOnly) {
      result = result.filter((f) => f.confirmed);
    }

    if (hideFalsePositives) {
      result = result.filter((f) => !f.false_positive);
    }

    if (sectionFilter) {
      result = result.filter((f) => {
        if (!f.section_id) return false;
        if (sectionFilter.endsWith(".*")) {
          const prefix = sectionFilter.slice(0, -2);
          return f.section_id.startsWith(prefix);
        }
        return f.section_id === sectionFilter;
      });
    }

    return result;
  }, [findings, severityFilter, workerFilter, confirmedOnly, hideFalsePositives, sectionFilter]);

  const table = useReactTable({
    data: filteredFindings,
    columns,
    getCoreRowModel: getCoreRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getSortedRowModel: getSortedRowModel(),
  });

  const uniqueWorkers = useMemo(
    () => [...new Set(findings.map((f) => f.worker_type).filter(Boolean))],
    [findings],
  );

  const uniqueSeverities = useMemo(
    () => [...new Set(findings.map((f) => f.severity))],
    [findings],
  );

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex flex-wrap gap-4 p-4 rounded-lg border border-border bg-bg-surface">
        <div>
          <label className="block text-xs text-text-secondary mb-1">Severity</label>
          <div className="flex gap-2">
            {uniqueSeverities.map((sev) => (
              <button
                key={sev}
                onClick={() =>
                  setSeverityFilter((prev) =>
                    prev.includes(sev) ? prev.filter((s) => s !== sev) : [...prev, sev],
                  )
                }
                className={`px-2 py-1 rounded text-xs font-medium ${
                  severityFilter.includes(sev)
                    ? SEVERITY_COLORS[sev]
                    : "bg-bg-void text-text-secondary"
                }`}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>

        <div>
          <label className="block text-xs text-text-secondary mb-1">Worker</label>
          <select
            multiple
            value={workerFilter}
            onChange={(e) =>
              setWorkerFilter(Array.from(e.target.selectedOptions, (o) => o.value))
            }
            className="rounded-md border border-border bg-bg-void px-2 py-1 text-xs text-text-primary"
          >
            {uniqueWorkers.filter((w): w is string => w !== null).map((w) => (
              <option key={w} value={w}>
                {w}
              </option>
            ))}
          </select>
        </div>

        <div className="flex items-center gap-4">
          <label className="flex items-center gap-1 text-xs text-text-secondary">
            <input
              type="checkbox"
              checked={confirmedOnly}
              onChange={(e) => setConfirmedOnly(e.target.checked)}
              className="rounded border-border"
            />
            Confirmed only
          </label>
          <label className="flex items-center gap-1 text-xs text-text-secondary">
            <input
              type="checkbox"
              checked={hideFalsePositives}
              onChange={(e) => setHideFalsePositives(e.target.checked)}
              className="rounded border-border"
            />
            Hide false positives
          </label>
        </div>

        <div>
          <label className="block text-xs text-text-secondary mb-1">Section Range</label>
          <input
            type="text"
            value={sectionFilter}
            onChange={(e) => setSectionFilter(e.target.value)}
            placeholder="e.g., 4.7.*"
            className="rounded-md border border-border bg-bg-void px-2 py-1 text-xs text-text-primary w-24"
          />
        </div>
      </div>

      {/* Table */}
      <div className="rounded-lg border border-border overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-bg-void">
            {table.getHeaderGroups().map((headerGroup) => (
              <tr key={headerGroup.id}>
                {headerGroup.headers.map((header) => (
                  <th
                    key={header.id}
                    className="px-3 py-2 text-left text-xs font-medium text-text-secondary uppercase tracking-wider"
                  >
                    {flexRender(header.column.columnDef.header, header.getContext())}
                  </th>
                ))}
              </tr>
            ))}
          </thead>
          <tbody className="divide-y divide-border bg-bg-surface">
            {table.getRowModel().rows.map((row) => (
              <tr key={row.id} className="hover:bg-bg-surface/80">
                {row.getVisibleCells().map((cell) => (
                  <td key={cell.id} className="px-3 py-2">
                    {flexRender(cell.column.columnDef.cell, cell.getContext())}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
        {filteredFindings.length === 0 && (
          <div className="text-center py-8 text-text-secondary">No findings match filters</div>
        )}
      </div>
    </div>
  );
}
