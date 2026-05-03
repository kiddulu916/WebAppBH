"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import PipelineGrid from "@/components/pipeline/PipelineGrid";
import WorkerDetailDrawer from "@/components/pipeline/WorkerDetailDrawer";
import { api } from "@/lib/api";
import { useCampaignStore } from "@/stores/campaign";
import type { Campaign, PipelineWorkerState } from "@/types/schema";
import { WORKER_STAGE_COUNTS } from "@/types/schema";
import { WORKER_STAGES } from "@/lib/worker-stages";

export default function CampaignOverviewPage() {
  const params = useParams();
  const campaignId = params.id as string;
  const [campaign, setCampaign] = useState<Campaign | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedWorker, setSelectedWorker] = useState<string | null>(null);
  const workerStates = useCampaignStore((s) => s.workerStates);
  const setActiveCampaign = useCampaignStore((s) => s.setActiveCampaign);

  useEffect(() => {
    const fetchCampaign = async () => {
      try {
        const data = await api.getCampaign(Number(campaignId));
        setCampaign(data);
        setActiveCampaign(data);
      } catch {
        // ignore — toast already shown by api client
      } finally {
        setLoading(false);
      }
    };
    fetchCampaign();
  }, [campaignId, setActiveCampaign]);

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
      {/* Campaign header */}
      {campaign && (
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-text-primary">{campaign.name}</h1>
            <p className="text-sm text-text-secondary mt-1">
              {campaign.description || "No description"}
            </p>
          </div>
          <div className="flex items-center gap-3">
            <span
              className={`px-3 py-1 rounded-full text-xs font-medium ${
                campaign.status === "running"
                  ? "bg-neon-orange-glow text-neon-orange"
                  : campaign.status === "complete"
                    ? "bg-neon-green-glow text-neon-green"
                    : campaign.status === "paused"
                      ? "bg-warning/20 text-warning"
                      : campaign.status === "cancelled"
                        ? "bg-danger/20 text-danger"
                        : "bg-bg-surface text-text-muted"
              }`}
            >
              {campaign.status}
            </span>
            {campaign.has_credentials && (
              <span className="px-3 py-1 rounded-full text-xs font-medium bg-neon-blue-glow text-neon-blue">
                Credentials
              </span>
            )}
          </div>
        </div>
      )}

      {/* Summary stats */}
      <div className="grid grid-cols-4 gap-4">
        <div className="rounded-lg border border-border p-4 bg-bg-surface">
          <div className="text-sm text-text-secondary">Workers Complete</div>
          <div className="text-2xl font-bold text-text-primary mt-1">
            {Object.values(workerStates).filter((w) => w.status === "complete").length}/
            {Object.keys(workerStates).length}
          </div>
        </div>
        <div className="rounded-lg border border-border p-4 bg-bg-surface">
          <div className="text-sm text-text-secondary">Running</div>
          <div className="text-2xl font-bold text-neon-orange mt-1">
            {Object.values(workerStates).filter((w) => w.status === "running").length}
          </div>
        </div>
        <div className="rounded-lg border border-border p-4 bg-bg-surface">
          <div className="text-sm text-text-secondary">Failed</div>
          <div className="text-2xl font-bold text-danger mt-1">
            {Object.values(workerStates).filter((w) => w.status === "failed").length}
          </div>
        </div>
        <div className="rounded-lg border border-border p-4 bg-bg-surface">
          <div className="text-sm text-text-secondary">Skipped</div>
          <div className="text-2xl font-bold text-text-muted mt-1">
            {Object.values(workerStates).filter((w) => w.skipped).length}
          </div>
        </div>
      </div>

      {/* Pipeline Grid */}
      <div className="rounded-lg border border-border p-6 bg-bg-surface">
        <h2 className="text-lg font-semibold text-text-primary mb-4">Pipeline Progress</h2>
        <PipelineGrid
          workerStates={workerStatesWithTotals}
          onWorkerClick={setSelectedWorker}
        />
      </div>

      {/* Worker Detail Drawer */}
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
