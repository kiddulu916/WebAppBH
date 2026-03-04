"use client";

import { useState } from "react";
import { X, Plus, Trash2 } from "lucide-react";
import { api } from "@/lib/api";
import { useCampaignStore } from "@/stores/campaign";
import type { TargetProfile } from "@/types/schema";

interface Props {
  open: boolean;
  onClose: () => void;
  targetId: number;
  currentProfile: TargetProfile | null;
}

export default function SettingsDrawer({ open, onClose, targetId, currentProfile }: Props) {
  const setActiveTarget = useCampaignStore((s) => s.setActiveTarget);
  const activeTarget = useCampaignStore((s) => s.activeTarget);

  const initialHeaders = Object.entries(currentProfile?.custom_headers ?? {}).map(([k, v]) => ({ key: k, value: v }));
  const [headers, setHeaders] = useState(initialHeaders.length > 0 ? initialHeaders : [{ key: "", value: "" }]);
  const [pps, setPps] = useState(String(currentProfile?.rate_limits?.pps ?? ""));
  const [saving, setSaving] = useState(false);

  function addHeader() {
    setHeaders([...headers, { key: "", value: "" }]);
  }

  function removeHeader(idx: number) {
    setHeaders(headers.filter((_, i) => i !== idx));
  }

  function updateHeader(idx: number, field: "key" | "value", val: string) {
    setHeaders(headers.map((h, i) => (i === idx ? { ...h, [field]: val } : h)));
  }

  async function handleSave() {
    setSaving(true);
    try {
      const custom_headers: Record<string, string> = {};
      for (const h of headers) {
        if (h.key.trim()) custom_headers[h.key.trim()] = h.value;
      }
      const rate_limits: Record<string, number> = {};
      if (pps) rate_limits.pps = Number(pps);
      const res = await api.updateTargetProfile(targetId, { custom_headers, rate_limits });
      if (activeTarget) {
        setActiveTarget({ ...activeTarget, target_profile: res.target_profile });
      }
      onClose();
    } catch {
      /* error handled by API client */
    } finally {
      setSaving(false);
    }
  }

  if (!open) return null;

  return (
    <>
      <div className="fixed inset-0 z-40 bg-black/50" onClick={onClose} />
      <div className="fixed inset-y-0 right-0 z-50 w-96 border-l border-border bg-bg-secondary shadow-lg">
        <div className="flex h-14 items-center justify-between border-b border-border px-4">
          <span className="text-sm font-semibold text-text-primary">Campaign Settings</span>
          <button onClick={onClose} className="rounded p-1 text-text-muted hover:bg-bg-surface hover:text-text-primary">
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="space-y-6 overflow-y-auto p-4">
          <div className="space-y-2">
            <label className="text-xs font-medium text-text-secondary">Custom Headers</label>
            {headers.map((h, i) => (
              <div key={i} className="flex items-center gap-2">
                <input
                  value={h.key}
                  onChange={(e) => updateHeader(i, "key", e.target.value)}
                  placeholder="Header name"
                  className="flex-1 rounded border border-border bg-bg-tertiary px-2 py-1.5 text-xs text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none"
                />
                <input
                  value={h.value}
                  onChange={(e) => updateHeader(i, "value", e.target.value)}
                  placeholder="Value"
                  className="flex-1 rounded border border-border bg-bg-tertiary px-2 py-1.5 text-xs text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none"
                />
                <button onClick={() => removeHeader(i)} className="rounded p-1 text-text-muted hover:text-danger">
                  <Trash2 className="h-3.5 w-3.5" />
                </button>
              </div>
            ))}
            <button onClick={addHeader} className="flex items-center gap-1 text-xs text-accent hover:underline">
              <Plus className="h-3 w-3" /> Add header
            </button>
          </div>
          <div className="space-y-2">
            <label className="text-xs font-medium text-text-secondary">Rate Limit (Packets Per Second)</label>
            <input
              type="number"
              value={pps}
              onChange={(e) => setPps(e.target.value)}
              placeholder="e.g. 50"
              className="w-full rounded border border-border bg-bg-tertiary px-2 py-1.5 text-xs text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none"
            />
          </div>
          <button
            onClick={handleSave}
            disabled={saving}
            className="w-full rounded-md bg-accent px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-accent/90 disabled:opacity-50"
          >
            {saving ? "Saving..." : "Save Settings"}
          </button>
        </div>
      </div>
    </>
  );
}
