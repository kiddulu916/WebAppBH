"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Loader2 } from "lucide-react";
import { type ColumnDef } from "@tanstack/react-table";
import DataTable from "@/components/findings/DataTable";
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

const columns: ColumnDef<AssetRow, unknown>[] = [
  { accessorKey: "id", header: "ID", size: 60 },
  {
    accessorKey: "asset_type",
    header: "Type",
    cell: ({ getValue }) => {
      const v = getValue() as string;
      return (
        <span className="rounded bg-accent/10 px-2 py-0.5 text-xs text-accent">
          {v}
        </span>
      );
    },
  },
  { accessorKey: "asset_value", header: "Value" },
  { accessorKey: "source_tool", header: "Source" },
  {
    accessorKey: "created_at",
    header: "Discovered",
    cell: ({ getValue }) => {
      const v = getValue() as string | null;
      return v ? new Date(v).toLocaleString() : "—";
    },
  },
];

export default function AssetsPage() {
  const router = useRouter();
  const { activeTarget } = useCampaignStore();
  const [data, setData] = useState<AssetRow[]>([]);
  const [loading, setLoading] = useState(true);

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

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold text-text-primary">Assets</h1>
      <p className="text-sm text-text-secondary">
        Discovered subdomains, IPs, and CIDRs
      </p>
      {loading ? (
        <div className="flex h-32 items-center justify-center">
          <Loader2 className="h-5 w-5 animate-spin text-accent" />
        </div>
      ) : (
        <DataTable data={data} columns={columns} />
      )}
    </div>
  );
}
