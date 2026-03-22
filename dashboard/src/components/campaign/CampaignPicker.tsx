"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Loader2, Plus, Globe } from "lucide-react";
import { api } from "@/lib/api";
import { useCampaignStore } from "@/stores/campaign";
import type { Target } from "@/types/schema";

export default function CampaignPicker() {
  const router = useRouter();
  const activeTarget = useCampaignStore((s) => s.activeTarget);
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
        <Loader2 className="h-5 w-5 animate-spin text-neon-orange" />
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

      <button
        onClick={() => router.push("/campaign")}
        className="flex w-full items-center justify-center gap-2 rounded-lg border border-dashed border-border bg-bg-tertiary p-3 text-sm text-text-muted transition-all hover:border-neon-orange/40 hover:text-neon-orange"
      >
        <Plus className="h-4 w-4" />
        Create New
      </button>

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {targets.map((t) => {
          const isSelected = activeTarget?.id === t.id;
          return (
            <button
              key={t.id}
              onClick={() => selectCampaign(t)}
              className={`group rounded-lg border p-4 text-left transition-all ${
                isSelected
                  ? "card-glow border-neon-orange/25 bg-bg-surface"
                  : "border-border bg-bg-secondary hover:border-border-accent"
              }`}
            >
              <div className="flex items-center gap-2">
                <Globe
                  className={`h-4 w-4 ${
                    isSelected ? "text-neon-orange" : "text-text-muted group-hover:text-neon-orange"
                  }`}
                />
                <span
                  className={`font-mono text-sm font-medium ${
                    isSelected
                      ? "text-neon-orange"
                      : "text-text-primary group-hover:text-neon-orange"
                  }`}
                >
                  {t.base_domain}
                </span>
              </div>
              <p className="mt-1 text-xs text-text-muted">{t.company_name}</p>
              {t.created_at && (
                <p className="mt-2 font-mono text-[10px] text-text-muted">
                  {new Date(t.created_at).toLocaleDateString()}
                </p>
              )}
            </button>
          );
        })}
      </div>
    </div>
  );
}
