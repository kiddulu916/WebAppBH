"use client";

import { type ColumnDef } from "@tanstack/react-table";
import DataTable from "@/components/findings/DataTable";
import type { Asset } from "@/types/schema";

const columns: ColumnDef<Asset, unknown>[] = [
  { accessorKey: "id", header: "ID", size: 60 },
  { accessorKey: "asset_type", header: "Type" },
  { accessorKey: "asset_value", header: "Value" },
  { accessorKey: "source_tool", header: "Source" },
  { accessorKey: "created_at", header: "Discovered",
    cell: ({ getValue }) => {
      const v = getValue() as string | null;
      return v ? new Date(v).toLocaleString() : "—";
    },
  },
];

// Placeholder — real data will come from API
const DEMO_DATA: Asset[] = [];

export default function AssetsPage() {
  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold text-text-primary">Assets</h1>
      <p className="text-sm text-text-secondary">
        Discovered subdomains, IPs, and CIDRs
      </p>
      <DataTable data={DEMO_DATA} columns={columns} />
    </div>
  );
}
