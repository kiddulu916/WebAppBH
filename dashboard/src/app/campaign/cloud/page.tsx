"use client";

import { type ColumnDef } from "@tanstack/react-table";
import DataTable from "@/components/findings/DataTable";
import type { CloudAsset } from "@/types/schema";

const columns: ColumnDef<CloudAsset, unknown>[] = [
  { accessorKey: "id", header: "ID", size: 60 },
  { accessorKey: "provider", header: "Provider" },
  { accessorKey: "asset_type", header: "Type" },
  { accessorKey: "url", header: "URL",
    cell: ({ getValue }) => {
      const v = getValue() as string | null;
      return v ? (
        <span className="truncate max-w-xs inline-block" title={v}>{v}</span>
      ) : "—";
    },
  },
  { accessorKey: "is_public", header: "Public",
    cell: ({ getValue }) =>
      getValue() ? (
        <span className="text-danger font-medium">Yes</span>
      ) : (
        <span className="text-success">No</span>
      ),
  },
  { accessorKey: "created_at", header: "Found",
    cell: ({ getValue }) => {
      const v = getValue() as string | null;
      return v ? new Date(v).toLocaleString() : "—";
    },
  },
];

const DEMO_DATA: CloudAsset[] = [];

export default function CloudPage() {
  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold text-text-primary">Cloud Assets</h1>
      <p className="text-sm text-text-secondary">
        AWS, Azure, and GCP resource findings
      </p>
      <DataTable data={DEMO_DATA} columns={columns} />
    </div>
  );
}
