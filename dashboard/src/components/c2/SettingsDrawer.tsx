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
  hasActiveJobs: boolean;
}

export default function SettingsDrawer({ open, onClose, targetId, currentProfile, hasActiveJobs }: Props) {
  const setActiveTarget = useCampaignStore((s) => s.setActiveTarget);
  const activeTarget = useCampaignStore((s) => s.activeTarget);

  const initialHeaders = Object.entries(currentProfile?.custom_headers ?? {}).map(([k, v]) => ({ key: k, value: v }));
  const [headers, setHeaders] = useState(initialHeaders.length > 0 ? initialHeaders : [{ key: "", value: "" }]);
  const [pps, setPps] = useState(String(currentProfile?.rate_limits?.pps ?? ""));
  const [saving, setSaving] = useState(false);
  const [cleanSlateConfirm, setCleanSlateConfirm] = useState(false);
  const [cleaning, setCleaning] = useState(false);

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
      // toast shown by api.request()
    } finally {
      setSaving(false);
    }
  }

  async function handleCleanSlate() {
    setCleaning(true);
    try {
      await api.cleanSlate(targetId);
      setCleanSlateConfirm(false);
      onClose();
    } catch {
      // toast shown by api.request()
    } finally {
      setCleaning(false);
    }
  }

  if (!open) return null;

  return (
    <>
      <div className="fixed inset-0 z-40 bg-black/50" onClick={onClose} />
      <div data-testid="settings-drawer" className="fixed inset-y-0 right-0 z-50 w-96 border-l border-border bg-bg-secondary shadow-lg">
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
                  data-testid={`settings-header-key-${i}`}
                  value={h.key}
                  onChange={(e) => updateHeader(i, "key", e.target.value)}
                  placeholder="Header name"
                  className="flex-1 rounded border border-border bg-bg-tertiary px-2 py-1.5 text-xs text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none"
                />
                <input
                  data-testid={`settings-header-value-${i}`}
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
              data-testid="settings-rate-input"
              type="number"
              value={pps}
              onChange={(e) => setPps(e.target.value)}
              placeholder="e.g. 50"
              className="w-full rounded border border-border bg-bg-tertiary px-2 py-1.5 text-xs text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none"
            />
          </div>
          <button
            data-testid="settings-save-btn"
            onClick={handleSave}
            disabled={saving}
            className="w-full rounded-md bg-accent px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-accent/90 disabled:opacity-50"
          >
            {saving ? "Saving..." : "Save Settings"}
          </button>

          {/* Danger Zone */}
          <div className="mt-8 border-t border-danger/20 pt-4">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-danger/60">Danger Zone</span>
            <div className="mt-3">
              <button
                onClick={() => setCleanSlateConfirm(true)}
                disabled={hasActiveJobs}
                className="w-full rounded-md border border-danger/30 px-4 py-2 text-sm font-medium text-danger transition-colors hover:bg-danger/10 disabled:cursor-not-allowed disabled:opacity-40"
                title={hasActiveJobs ? "Kill current run first" : ""}
              >
                Reset Target Data
              </button>
              <p className="mt-1 text-[10px] text-text-muted">
                Deletes all assets, vulnerabilities, jobs, and alerts. Preserves configuration and bounties.
              </p>
            </div>
          </div>
        </div>
      </div>

      {cleanSlateConfirm && (
        <>
          <div className="fixed inset-0 z-[60] bg-black/60" onClick={() => setCleanSlateConfirm(false)} />
          <div className="fixed left-1/2 top-1/2 z-[60] w-80 -translate-x-1/2 -translate-y-1/2 rounded-lg border border-danger/30 bg-bg-secondary p-5 shadow-xl">
            <h3 className="text-sm font-semibold text-text-primary">Reset Target Data</h3>
            <p className="mt-2 text-xs text-text-muted">
              This will permanently delete all discovered assets, vulnerabilities, jobs, and alerts for this target. Configuration and bounty submissions are preserved. This cannot be undone.
            </p>
            <div className="mt-4 flex justify-end gap-2">
              <button
                onClick={() => setCleanSlateConfirm(false)}
                className="rounded px-3 py-1.5 text-xs text-text-muted transition-colors hover:bg-bg-surface"
              >
                Cancel
              </button>
              <button
                onClick={handleCleanSlate}
                disabled={cleaning}
                className="rounded bg-danger px-3 py-1.5 text-xs font-medium text-white transition-colors hover:bg-danger/90 disabled:opacity-50"
              >
                {cleaning ? "Resetting..." : "Delete All Data"}
              </button>
            </div>
          </div>
        </>
      )}
    </>
  );
}
