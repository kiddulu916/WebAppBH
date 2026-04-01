"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import ChainList from "@/components/chains/ChainList";
import type { ChainFindingView } from "@/types/campaign";

export default function ChainsPage() {
  const params = useParams();
  const campaignId = params.id as string;
  const [chains, setChains] = useState<ChainFindingView[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchChains = async () => {
      try {
        const res = await fetch(`/api/campaigns/${campaignId}/chains`);
        if (res.ok) {
          const data = await res.json();
          setChains(data);
        }
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
