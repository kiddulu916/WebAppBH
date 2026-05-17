// dashboard/src/app/campaign/assets/[id]/page.tsx
"use client";

import { useEffect, useState, useCallback } from "react";
import { useParams, useRouter } from "next/navigation";
import { ChevronLeft, Loader2, AlertTriangle } from "lucide-react";
import { api, type PathNodeTree } from "@/lib/api";
import { useCampaignStore } from "@/stores/campaign";
import DirectoryTree from "@/components/assets/DirectoryTree";
import PortsList from "@/components/assets/PortsList";
import AssetNodeDrawer, { type DrawerState } from "@/components/assets/AssetNodeDrawer";
import type { Location } from "@/types/schema";

export default function AssetDetailPage() {
  const params = useParams<{ id: string }>();
  const router = useRouter();
  const activeTarget = useCampaignStore((s) => s.activeTarget);

  const assetId = parseInt(params.id, 10);

  const [assetValue, setAssetValue] = useState<string | null>(null);
  const [treeNodes, setTreeNodes] = useState<PathNodeTree[]>([]);
  const [locations, setLocations] = useState<Location[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [selectedNodeId, setSelectedNodeId] = useState<number | null>(null);
  const [selectedPortId, setSelectedPortId] = useState<number | null>(null);
  const [drawerState, setDrawerState] = useState<DrawerState | null>(null);
  const [drawerLoading, setDrawerLoading] = useState(false);

  useEffect(() => {
    if (!activeTarget || isNaN(assetId)) return;

    setLoading(true);
    setError(false);

    Promise.all([
      api.getAllAssets(activeTarget.id),
      api.getPathNodes(activeTarget.id),
      api.getAssetLocations(assetId),
    ])
      .then(([assets, treeRes, locsRes]) => {
        const found = assets.find((a) => a.id === assetId) ?? null;
        setAssetValue(found?.asset_value ?? null);
        setTreeNodes(treeRes.nodes);
        setLocations(locsRes.locations);
      })
      .catch(() => setError(true))
      .finally(() => setLoading(false));
  }, [activeTarget, assetId]);

  const handleNodeSelect = useCallback(async (nodeId: number) => {
    setSelectedNodeId(nodeId);
    setSelectedPortId(null);
    setDrawerLoading(true);
    try {
      const detail = await api.getPathNode(nodeId);
      setDrawerState({ type: "node", detail });
    } catch {
      setDrawerState(null);
    } finally {
      setDrawerLoading(false);
    }
  }, []);

  const handlePortSelect = useCallback((loc: Location) => {
    setSelectedPortId(loc.id);
    setSelectedNodeId(null);
    setDrawerState({ type: "port", location: loc });
  }, []);

  const closeDrawer = useCallback(() => {
    setDrawerState(null);
    setSelectedNodeId(null);
    setSelectedPortId(null);
  }, []);

  if (!activeTarget) {
    return (
      <div className="flex h-64 items-center justify-center">
        <p className="text-text-muted">No active campaign selected.</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="space-y-5">
        <BackLink />
        <div className="flex flex-col items-center justify-center gap-4 rounded-lg border border-danger/30 bg-danger/5 py-16">
          <AlertTriangle className="h-10 w-10 text-danger" />
          <p className="text-text-primary font-medium">Failed to load asset.</p>
          <button
            onClick={() => router.back()}
            className="rounded-md border border-border bg-bg-surface px-4 py-2 text-sm text-text-primary hover:bg-bg-tertiary transition-colors"
          >
            Go back
          </button>
        </div>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="space-y-5">
        <BackLink />
        <div className="flex h-64 items-center justify-center">
          <Loader2 className="h-6 w-6 animate-spin text-neon-orange" />
        </div>
      </div>
    );
  }

  return (
    <div className="flex h-[calc(100vh-8rem)] flex-col gap-4 animate-fade-in">
      {/* Header */}
      <div className="flex-shrink-0">
        <BackLink />
        <h1 className="mt-2 font-mono text-lg text-text-primary break-all">
          {assetValue ?? `Asset #${assetId}`}
        </h1>
      </div>

      {/* Two-column body */}
      <div className="flex min-h-0 flex-1 gap-4">
        {/* Directory Tree */}
        <div className="flex-1 overflow-y-auto rounded-lg border border-border bg-bg-secondary p-4">
          <div className="section-label mb-3">DIRECTORY TREE</div>
          <DirectoryTree
            nodes={treeNodes}
            selectedId={selectedNodeId}
            onSelect={handleNodeSelect}
          />
        </div>

        {/* Ports */}
        <div className="w-56 flex-shrink-0 overflow-y-auto rounded-lg border border-border bg-bg-secondary p-4">
          <div className="section-label mb-3">PORTS</div>
          {drawerLoading && (
            <div className="flex justify-center py-2">
              <Loader2 className="h-4 w-4 animate-spin text-neon-orange" />
            </div>
          )}
          <PortsList
            locations={locations}
            selectedId={selectedPortId}
            onSelect={handlePortSelect}
          />
        </div>
      </div>

      {/* Side drawer */}
      <AssetNodeDrawer state={drawerState} onClose={closeDrawer} />
    </div>
  );
}

function BackLink() {
  const router = useRouter();
  return (
    <button
      onClick={() => router.push("/campaign/assets")}
      className="flex items-center gap-1 text-sm text-text-muted hover:text-text-primary transition-colors"
    >
      <ChevronLeft className="h-4 w-4" />
      Assets
    </button>
  );
}
