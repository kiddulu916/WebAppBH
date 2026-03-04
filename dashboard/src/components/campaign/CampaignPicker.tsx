"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Loader2, Plus, Globe } from "lucide-react";
import { api } from "@/lib/api";
import { useCampaignStore } from "@/stores/campaign";
import type { Target } from "@/types/schema";

export default function CampaignPicker() {
  const router = useRouter();
  const setActiveTarget = useCampaignStore((s) => s.setActiveTarget);
  const [targets, setTargets] = useState<Target[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .getTargets()
      .then((res) => {
        setTargets(res.targets);
        if (res.targets.length === 0) {
          router.push("/campaign");
        }
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [router]);

  function selectCampaign(target: Target) {
    setActiveTarget(target);
    router.push("/campaign/c2");
  }

  if (loading) {
    return (
      <div className="flex h-40 items-center justify-center">
        <Loader2 className="h-5 w-5 animate-spin text-accent" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-lg font-semibold text-text-primary">
          Select a Campaign
        </h2>
        <p className="text-sm text-text-muted">
          Choose an existing campaign or start a new one
        </p>
      </div>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {targets.map((t) => (
          <button
            key={t.id}
            onClick={() => selectCampaign(t)}
            className="group rounded-lg border border-border bg-bg-secondary p-4 text-left transition-colors hover:border-accent/50"
          >
            <div className="flex items-center gap-2">
              <Globe className="h-4 w-4 text-accent" />
              <span className="text-sm font-medium text-text-primary group-hover:text-accent">
                {t.base_domain}
              </span>
            </div>
            <p className="mt-1 text-xs text-text-muted">{t.company_name}</p>
            {t.created_at && (
              <p className="mt-2 text-[10px] text-text-muted">
                {new Date(t.created_at).toLocaleDateString()}
              </p>
            )}
          </button>
        ))}
        <button
          onClick={() => router.push("/campaign")}
          className="group flex items-center justify-center gap-2 rounded-lg border border-dashed border-border bg-bg-secondary p-4 transition-colors hover:border-accent/50"
        >
          <Plus className="h-4 w-4 text-text-muted group-hover:text-accent" />
          <span className="text-sm text-text-muted group-hover:text-accent">
            New Campaign
          </span>
        </button>
      </div>
    </div>
  );
}
