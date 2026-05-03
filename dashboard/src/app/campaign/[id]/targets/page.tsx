"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import TargetTree from "@/components/targets/TargetTree";
import type { TargetNode } from "@/types/schema";
import { api } from "@/lib/api";

export default function TargetsPage() {
  const params = useParams();
  const campaignId = params.id as string;
  const [targets, setTargets] = useState<TargetNode[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchTargets = async () => {
      try {
        const data = await api.getTargets();
        setTargets(data.targets.map(t => ({
          id: t.id,
          domain: t.base_domain,
          target_type: "seed" as const,
          priority: 0,
          status: t.status || "pending",
          wildcard: false,
          wildcard_count: null,
          parent_target_id: null,
          worker_states: {},
          vulnerability_count: t.vuln_count || 0,
        })));
      } catch {
        // ignore
      } finally {
        setLoading(false);
      }
    };
    fetchTargets();
  }, [campaignId]);

  if (loading) {
    return <div className="flex items-center justify-center h-64 text-text-secondary">Loading...</div>;
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-text-primary">Target Hierarchy</h1>
        <p className="text-sm text-text-secondary mt-1">
          Seed targets and discovered child domains
        </p>
      </div>

      <div className="rounded-lg border border-border p-6 bg-bg-surface">
        {targets.length === 0 ? (
          <div className="text-center text-text-secondary py-8">No targets found</div>
        ) : (
          <TargetTree targets={targets} campaignId={campaignId} />
        )}
      </div>
    </div>
  );
}
