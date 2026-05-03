"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import ChainList from "@/components/chains/ChainList";
import type { ChainFindingView } from "@/types/schema";
import { api } from "@/lib/api";

export default function ChainsPage() {
  const params = useParams();
  const campaignId = params.id as string;
  const [chains, setChains] = useState<ChainFindingView[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchChains = async () => {
      try {
        const targetsRes = await api.getTargets();
        const allChains: ChainFindingView[] = [];
        for (const target of targetsRes.targets) {
          try {
            const pathsRes = await api.getAttackPaths(target.id);
            for (const path of pathsRes.paths) {
              allChains.push({
                id: path.id,
                target_id: target.id,
                chain_description: path.description,
                severity: path.severity,
                total_impact: null,
                linked_vulnerability_ids: path.steps.map(s => s.vuln_id),
                created_at: new Date().toISOString(),
              });
            }
          } catch {
            // target may not have attack paths
          }
        }
        setChains(allChains);
      } catch {
        // ignore
      } finally {
        setLoading(false);
      }
    };
    fetchChains();
  }, [campaignId]);

  if (loading) {
    return <div className="flex items-center justify-center h-64 text-text-secondary">Loading...</div>;
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-text-primary">Chain Findings</h1>
        <p className="text-sm text-text-secondary mt-1">
          {chains.length} attack chains identified
        </p>
      </div>

      <div className="rounded-lg border border-border p-6 bg-bg-surface">
        <ChainList chains={chains} campaignId={campaignId} />
      </div>
    </div>
  );
}
