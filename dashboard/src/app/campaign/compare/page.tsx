"use client";

import { useEffect, useState, useMemo } from "react";
import { GitCompareArrows, Loader2 } from "lucide-react";
import { api, type AssetWithLocations } from "@/lib/api";
import type { Target } from "@/types/schema";

export default function ComparePage() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [targetA, setTargetA] = useState<number | null>(null);
  const [targetB, setTargetB] = useState<number | null>(null);
  const [assetsA, setAssetsA] = useState<AssetWithLocations[]>([]);
  const [assetsB, setAssetsB] = useState<AssetWithLocations[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    api.getTargets().then((r) => setTargets(r.targets)).catch(() => {});
  }, []);

  useEffect(() => {
    if (targetA == null) { setAssetsA([]); return; }
    setLoading(true);
    api.getAssets(targetA).then((r) => setAssetsA(r.assets)).catch(() => {}).finally(() => setLoading(false));
  }, [targetA]);

  useEffect(() => {
    if (targetB == null) { setAssetsB([]); return; }
    setLoading(true);
    api.getAssets(targetB).then((r) => setAssetsB(r.assets)).catch(() => {}).finally(() => setLoading(false));
  }, [targetB]);

  const diff = useMemo(() => {
    const setA = new Set(assetsA.map((a) => a.asset_value));
    const setB = new Set(assetsB.map((a) => a.asset_value));
    const shared = [...setA].filter((v) => setB.has(v));
    const onlyA = [...setA].filter((v) => !setB.has(v));
    const onlyB = [...setB].filter((v) => !setA.has(v));
    return { shared, onlyA, onlyB };
  }, [assetsA, assetsB]);

  return (
    <div className="space-y-5 animate-fade-in">
      <div>
        <h1 className="flex items-center gap-2 text-2xl font-bold text-text-primary">
          <GitCompareArrows className="h-5 w-5 text-neon-blue" />
          Target Comparison
        </h1>
        <p className="mt-1 text-sm text-text-secondary">
          Side-by-side diff of two targets&apos; asset inventories
        </p>
      </div>

      {/* Selectors */}
      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="section-label mb-1.5 block">Target A</label>
          <select
            value={targetA ?? ""}
            onChange={(e) => setTargetA(e.target.value ? Number(e.target.value) : null)}
            className="w-full rounded-md border border-border bg-bg-tertiary px-3 py-2 text-sm text-text-primary"
          >
            <option value="">Select target...</option>
            {targets.map((t) => (
              <option key={t.id} value={t.id}>
                {t.company_name} — {t.base_domain}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label className="section-label mb-1.5 block">Target B</label>
          <select
            value={targetB ?? ""}
            onChange={(e) => setTargetB(e.target.value ? Number(e.target.value) : null)}
            className="w-full rounded-md border border-border bg-bg-tertiary px-3 py-2 text-sm text-text-primary"
          >
            <option value="">Select target...</option>
            {targets.map((t) => (
              <option key={t.id} value={t.id}>
                {t.company_name} — {t.base_domain}
              </option>
            ))}
          </select>
        </div>
      </div>

      {loading && (
        <div className="flex justify-center py-8">
          <Loader2 className="h-5 w-5 animate-spin text-neon-blue" />
        </div>
      )}

      {/* Results */}
      {targetA != null && targetB != null && !loading && (
        <div className="grid grid-cols-3 gap-4">
          {/* Only in A */}
          <div className="rounded-lg border border-border bg-bg-secondary p-4">
            <div className="mb-3 flex items-center gap-2">
              <span className="h-2 w-2 rounded-full bg-neon-orange" />
              <span className="section-label">ONLY IN A</span>
              <span className="ml-auto font-mono text-xs text-text-muted">{diff.onlyA.length}</span>
            </div>
            <div className="max-h-96 space-y-1 overflow-y-auto">
              {diff.onlyA.map((v) => (
                <div key={v} className="rounded bg-bg-void px-2 py-1 font-mono text-xs text-neon-orange">
                  {v}
                </div>
              ))}
              {diff.onlyA.length === 0 && (
                <p className="text-xs text-text-muted">No unique assets</p>
              )}
            </div>
          </div>

          {/* Shared */}
          <div className="rounded-lg border border-border bg-bg-secondary p-4">
            <div className="mb-3 flex items-center gap-2">
              <span className="h-2 w-2 rounded-full bg-neon-green" />
              <span className="section-label">SHARED</span>
              <span className="ml-auto font-mono text-xs text-text-muted">{diff.shared.length}</span>
            </div>
            <div className="max-h-96 space-y-1 overflow-y-auto">
              {diff.shared.map((v) => (
                <div key={v} className="rounded bg-bg-void px-2 py-1 font-mono text-xs text-neon-green">
                  {v}
                </div>
              ))}
              {diff.shared.length === 0 && (
                <p className="text-xs text-text-muted">No shared assets</p>
              )}
            </div>
          </div>

          {/* Only in B */}
          <div className="rounded-lg border border-border bg-bg-secondary p-4">
            <div className="mb-3 flex items-center gap-2">
              <span className="h-2 w-2 rounded-full bg-neon-blue" />
              <span className="section-label">ONLY IN B</span>
              <span className="ml-auto font-mono text-xs text-text-muted">{diff.onlyB.length}</span>
            </div>
            <div className="max-h-96 space-y-1 overflow-y-auto">
              {diff.onlyB.map((v) => (
                <div key={v} className="rounded bg-bg-void px-2 py-1 font-mono text-xs text-neon-blue">
                  {v}
                </div>
              ))}
              {diff.onlyB.length === 0 && (
                <p className="text-xs text-text-muted">No unique assets</p>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Summary stats */}
      {targetA != null && targetB != null && !loading && (
        <div className="grid grid-cols-4 gap-3">
          {[
            { label: "Target A Assets", value: assetsA.length, color: "text-neon-orange" },
            { label: "Target B Assets", value: assetsB.length, color: "text-neon-blue" },
            { label: "Shared", value: diff.shared.length, color: "text-neon-green" },
            { label: "Overlap", value: assetsA.length > 0 ? `${Math.round((diff.shared.length / assetsA.length) * 100)}%` : "—", color: "text-text-primary" },
          ].map((stat) => (
            <div key={stat.label} className="rounded-lg border border-border bg-bg-surface p-3 text-center">
              <div className={`text-xl font-bold font-mono ${stat.color}`}>{stat.value}</div>
              <div className="text-[10px] text-text-muted">{stat.label}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
