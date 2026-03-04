"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Loader2 } from "lucide-react";
import { type ColumnDef } from "@tanstack/react-table";
import DataTable from "@/components/findings/DataTable";
import { api } from "@/lib/api";
import { useCampaignStore } from "@/stores/campaign";
import type { CloudAsset, CloudProvider } from "@/types/schema";

const PROVIDER_COLORS: Record<CloudProvider, string> = {
  AWS: "bg-warning/20 text-warning",
  Azure: "bg-accent/20 text-accent",
  GCP: "bg-danger/20 text-danger",
  Other: "bg-bg-surface text-text-muted",
};

const columns: ColumnDef<CloudAsset, unknown>[] = [
  { accessorKey: "id", header: "ID", size: 60 },
  {
    accessorKey: "provider",
    header: "Provider",
    cell: ({ getValue }) => {
      const p = getValue() as CloudProvider;
      return (
        <span
          className={`rounded px-2 py-0.5 text-xs font-medium ${PROVIDER_COLORS[p] ?? PROVIDER_COLORS.Other}`}
        >
          {p}
        </span>
      );
    },
  },
  { accessorKey: "asset_type", header: "Type" },
  {
    accessorKey: "url",
    header: "URL",
    cell: ({ getValue }) => {
      const v = getValue() as string | null;
      return v ? (
        <span className="inline-block max-w-xs truncate" title={v}>
          {v}
        </span>
      ) : (
        "—"
      );
    },
  },
  {
    accessorKey: "is_public",
    header: "Public",
    cell: ({ getValue }) =>
      getValue() ? (
        <span className="font-medium text-danger">Yes</span>
      ) : (
        <span className="text-success">No</span>
      ),
  },
  {
    accessorKey: "created_at",
    header: "Found",
    cell: ({ getValue }) => {
      const v = getValue() as string | null;
      return v ? new Date(v).toLocaleString() : "—";
    },
  },
];

export default function CloudPage() {
  const router = useRouter();
  const { activeTarget } = useCampaignStore();
  const [data, setData] = useState<CloudAsset[]>([]);
  const [loading, setLoading] = useState(true);

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

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-bold text-text-primary">Cloud Assets</h1>
      <p className="text-sm text-text-secondary">
        AWS, Azure, and GCP resource findings
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
