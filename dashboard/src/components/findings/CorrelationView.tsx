"use client";

import { useEffect, useState } from "react";
import { Loader2, Link2, AlertCircle } from "lucide-react";
import { api } from "@/lib/api";
import { useCampaignStore } from "@/stores/campaign";

interface CorrelationGroup {
  shared_assets: string[];
  severity: string;
  count: number;
  vuln_ids: number[];
  chain_description: string;
}

const SEVERITY_BADGE: Record<string, string> = {
  critical: "bg-sev-critical/20 text-sev-critical border-sev-critical/30",
  high: "bg-sev-high/20 text-sev-high border-sev-high/30",
  medium: "bg-sev-medium/20 text-sev-medium border-sev-medium/30",
  low: "bg-sev-low/20 text-sev-low border-sev-low/30",
  info: "bg-bg-surface text-text-muted border-border",
};

export default function CorrelationView() {
  const activeTarget = useCampaignStore((s) => s.activeTarget);
  const [groups, setGroups] = useState<CorrelationGroup[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!activeTarget) return;
    let cancelled = false;
    queueMicrotask(() => setLoading(true));
    api
      .getCorrelations(activeTarget.id)
      .then((res) => { if (!cancelled) setGroups(res.groups); })
      .catch(() => {})
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [activeTarget]);

  if (loading) {
    return (
      <div className="flex h-40 items-center justify-center">
        <Loader2 className="h-5 w-5 animate-spin text-accent" />
      </div>
    );
  }

  if (groups.length === 0) {
    return (
      <div className="rounded-lg border border-border bg-bg-secondary p-6 text-center">
        <Link2 className="mx-auto h-6 w-6 text-text-muted" />
        <p className="mt-2 text-sm text-text-muted">No correlated findings yet</p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <Link2 className="h-4 w-4 text-accent" />
        <span className="text-sm font-semibold text-text-primary">
          Correlated Findings ({groups.length} groups)
        </span>
      </div>
      <div className="space-y-2">
        {groups.map((g, i) => (
          <div key={i} className="rounded-lg border border-border bg-bg-secondary p-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <AlertCircle className="h-4 w-4 text-text-muted" />
                <span className="font-mono text-xs text-text-primary">
                  {g.shared_assets.join(", ")}
                </span>
              </div>
              <div className="flex items-center gap-2">
                <span
                  className={`rounded border px-2 py-0.5 text-[10px] font-medium ${
                    SEVERITY_BADGE[g.severity] || SEVERITY_BADGE.info
                  }`}
                >
                  {g.severity.toUpperCase()}
                </span>
                <span className="text-xs text-text-muted">{g.count} vulns</span>
              </div>
            </div>
            <p className="mt-2 text-xs text-text-secondary">{g.chain_description}</p>
          </div>
        ))}
      </div>
    </div>
  );
}
