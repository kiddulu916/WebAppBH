"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import ChainDetail from "@/components/chains/ChainDetail";
import type { ChainFindingView, Finding } from "@/types/schema";

export default function ChainDetailPage() {
  const params = useParams();
  const campaignId = params.id as string;
  const chainId = params.chainId as string;
  const [chain, setChain] = useState<ChainFindingView | null>(null);
  const [linkedFindings, setLinkedFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchChain = async () => {
      try {
        const res = await fetch(`/api/campaigns/${campaignId}/chains/${chainId}`);
        if (res.ok) {
          const data = await res.json();
          setChain(data.chain);
          setLinkedFindings(data.linked_findings || []);
        }
      } catch {
        // ignore
      } finally {
        setLoading(false);
      }
    };
    fetchChain();
  }, [campaignId, chainId]);

  if (loading) {
    return <div className="flex items-center justify-center h-64 text-text-secondary">Loading...</div>;
  }

  if (!chain) {
    return <div className="text-center py-8 text-text-secondary">Chain not found</div>;
  }

  return <ChainDetail chain={chain} linkedFindings={linkedFindings} />;
}
