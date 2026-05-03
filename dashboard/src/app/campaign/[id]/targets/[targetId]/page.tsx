"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import PipelineGrid from "@/components/pipeline/PipelineGrid";
import WorkerDetailDrawer from "@/components/pipeline/WorkerDetailDrawer";
import { useCampaignStore } from "@/stores/campaign";
import type { PipelineWorkerState } from "@/types/schema";
import { WORKER_STAGE_COUNTS } from "@/types/schema";
import { WORKER_STAGES } from "@/lib/worker-stages";

/** Shape returned by the campaign-targets API endpoint. */
interface TargetNode {
  domain: string;
  target_type: string;
  priority: number;
  vulnerability_count: number;
}

export default function ChildTargetPage() {
  const params = useParams();
  const campaignId = params.id as string;
  const targetId = params.targetId as string;
  const [target, setTarget] = useState<TargetNode | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedWorker, setSelectedWorker] = useState<string | null>(null);
  const workerStates = useCampaignStore((s) => s.workerStates);

  useEffect(() => {
    const fetchTarget = async () => {
      try {
        const res = await fetch(`/api/campaigns/${campaignId}/targets/${targetId}`);
        if (res.ok) {
          const data = await res.json();
          setTarget(data);
        }
      } catch {
        // ignore
      } finally {
        setLoading(false);
      }
    };
    fetchTarget();
  }, [campaignId, targetId]);

  const workerStatesWithTotals = Object.entries(workerStates).reduce((acc, [key, value]) => {
    acc[key] = {
      ...value,
      total_stages: WORKER_STAGE_COUNTS[key] || 0,
    };
    return acc;
  }, {} as Record<string, PipelineWorkerState & { total_stages: number }>);

  if (loading) {
    return <div className="flex items-center justify-center h-64 text-text-secondary">Loading...</div>;
  }

  return (
    <div className="space-y-6">
      {target && (
        <div>
          <h1 className="text-2xl font-bold text-text-primary">{target.domain}</h1>
          <p className="text-sm text-text-secondary mt-1">
            {target.target_type} | Priority: P:{target.priority} | {target.vulnerability_count} vulnerabilities
          </p>
        </div>
      )}

      <div className="rounded-lg border border-border p-6 bg-bg-surface">
        <h2 className="text-lg font-semibold text-text-primary mb-4">Pipeline Progress</h2>
        <PipelineGrid
          workerStates={workerStatesWithTotals}
          onWorkerClick={setSelectedWorker}
        />
      </div>

      {selectedWorker && (
        <WorkerDetailDrawer
          worker={selectedWorker}
          state={workerStates[selectedWorker] || { status: "pending" }}
          stages={WORKER_STAGES[selectedWorker] || []}
          findingCount={0}
          onClose={() => setSelectedWorker(null)}
        />
      )}
    </div>
  );
}
