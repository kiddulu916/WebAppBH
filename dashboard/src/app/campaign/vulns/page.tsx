"use client";

import { type ColumnDef } from "@tanstack/react-table";
import DataTable from "@/components/findings/DataTable";
import type { Vulnerability, VulnSeverity } from "@/types/schema";

const SEV_COLORS: Record<VulnSeverity, string> = {
  critical: "bg-critical/20 text-critical",
  high: "bg-danger/20 text-danger",
  medium: "bg-warning/20 text-warning",
  low: "bg-info/20 text-info",
  info: "bg-bg-surface text-text-muted",
};

const columns: ColumnDef<Vulnerability, unknown>[] = [
  { accessorKey: "id", header: "ID", size: 60 },
  {
    accessorKey: "severity",
    header: "Severity",
    cell: ({ getValue }) => {
      const s = getValue() as VulnSeverity;
      return (
        <span className={`rounded px-2 py-0.5 text-xs font-medium ${SEV_COLORS[s] ?? ""}`}>
          {s.toUpperCase()}
        </span>
      );
    },
  },
  { accessorKey: "title", header: "Title" },
  { accessorKey: "source_tool", header: "Source" },
  { accessorKey: "created_at", header: "Found",
    cell: ({ getValue }) => {
      const v = getValue() as string | null;
      return v ? new Date(v).toLocaleString() : "—";
    },
  },
];

const DEMO_DATA: Vulnerability[] = [];

export default function VulnsPage() {
  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold text-text-primary">Vulnerabilities</h1>
      <p className="text-sm text-text-secondary">
        Findings grouped by severity
      </p>
      <DataTable data={DEMO_DATA} columns={columns} />
    </div>
  );
}
