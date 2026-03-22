"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import {
  CalendarClock,
  Loader2,
  Plus,
  Trash2,
  Power,
  PowerOff,
} from "lucide-react";
import { api, type ScheduleRow } from "@/lib/api";
import { useCampaignStore } from "@/stores/campaign";

export default function SchedulesPage() {
  const router = useRouter();
  const activeTarget = useCampaignStore((s) => s.activeTarget);
  const [schedules, setSchedules] = useState<ScheduleRow[]>([]);
  const [loading, setLoading] = useState(true);

  // Create form state
  const [showCreate, setShowCreate] = useState(false);
  const [cronExpr, setCronExpr] = useState("0 0 * * *");
  const [playbook, setPlaybook] = useState("wide_recon");
  const [creating, setCreating] = useState(false);

  useEffect(() => {
    if (!activeTarget) {
      router.push("/");
      return;
    }
    let cancelled = false;
    api
      .getSchedules(activeTarget.id)
      .then((res) => {
        if (!cancelled) setSchedules(res.schedules);
      })
      .catch(() => {})
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [activeTarget, router]);

  const handleCreate = async () => {
    if (!activeTarget || !cronExpr.trim()) return;
    setCreating(true);
    try {
      await api.createSchedule({
        target_id: activeTarget.id,
        cron_expression: cronExpr.trim(),
        playbook,
      });
      // Refresh list
      const updated = await api.getSchedules(activeTarget.id);
      setSchedules(updated.schedules);
      setShowCreate(false);
      setCronExpr("0 0 * * *");
    } catch {}
    setCreating(false);
  };

  const handleToggle = async (schedule: ScheduleRow) => {
    try {
      const updated = await api.updateSchedule(schedule.id, {
        enabled: !schedule.enabled,
      });
      setSchedules((prev) =>
        prev.map((s) => (s.id === schedule.id ? updated : s)),
      );
    } catch {}
  };

  const handleDelete = async (id: number) => {
    try {
      await api.deleteSchedule(id);
      setSchedules((prev) => prev.filter((s) => s.id !== id));
    } catch {}
  };

  if (!activeTarget) {
    return (
      <div className="flex h-64 items-center justify-center">
        <p className="text-text-muted">No active campaign selected.</p>
      </div>
    );
  }

  return (
    <div className="space-y-5 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-bold text-text-primary">
            <CalendarClock className="h-5 w-5 text-neon-blue" />
            Scheduled Scans
          </h1>
          <p className="mt-1 text-sm text-text-secondary">
            Manage recurring scan schedules
          </p>
        </div>
        <button
          onClick={() => setShowCreate(!showCreate)}
          className="flex items-center gap-1.5 rounded-md bg-neon-orange px-3 py-1.5 text-xs font-semibold text-bg-primary hover:bg-neon-orange-dim"
        >
          <Plus className="h-3.5 w-3.5" />
          New Schedule
        </button>
      </div>

      {/* Create form */}
      {showCreate && (
        <div className="rounded-lg border border-neon-orange/20 bg-bg-secondary p-4 space-y-3 animate-fade-in">
          <h3 className="text-sm font-semibold text-text-primary">
            Create Schedule
          </h3>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="section-label mb-1 block">Cron Expression</label>
              <input
                type="text"
                value={cronExpr}
                onChange={(e) => setCronExpr(e.target.value)}
                placeholder="0 0 * * *"
                className="w-full rounded-md border border-border bg-bg-tertiary px-3 py-2 font-mono text-sm text-text-primary placeholder:text-text-muted input-focus"
              />
              <p className="mt-1 text-[10px] text-text-muted">
                min hour day month weekday
              </p>
            </div>
            <div>
              <label className="section-label mb-1 block">Playbook</label>
              <select
                value={playbook}
                onChange={(e) => setPlaybook(e.target.value)}
                className="w-full rounded-md border border-border bg-bg-tertiary px-3 py-2 text-sm text-text-primary"
              >
                <option value="wide_recon">Wide Recon</option>
                <option value="deep_webapp">Deep WebApp</option>
                <option value="api_focused">API Focused</option>
                <option value="cloud_first">Cloud First</option>
              </select>
            </div>
          </div>
          <div className="flex justify-end gap-2">
            <button
              onClick={() => setShowCreate(false)}
              className="rounded-md px-3 py-1.5 text-xs text-text-muted hover:text-text-primary"
            >
              Cancel
            </button>
            <button
              onClick={handleCreate}
              disabled={creating || !cronExpr.trim()}
              className="flex items-center gap-1.5 rounded-md bg-neon-green px-3 py-1.5 text-xs font-semibold text-bg-primary hover:bg-neon-green-dim disabled:opacity-50"
            >
              {creating && <Loader2 className="h-3 w-3 animate-spin" />}
              Create
            </button>
          </div>
        </div>
      )}

      {/* Table */}
      {loading ? (
        <div className="flex h-32 items-center justify-center">
          <Loader2 className="h-5 w-5 animate-spin text-neon-blue" />
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-left text-sm">
            <thead className="bg-bg-surface text-xs text-text-secondary">
              <tr>
                <th className="px-4 py-3 font-medium">Status</th>
                <th className="px-4 py-3 font-medium">Cron</th>
                <th className="px-4 py-3 font-medium">Playbook</th>
                <th className="px-4 py-3 font-medium">Last Run</th>
                <th className="px-4 py-3 font-medium">Next Run</th>
                <th className="px-4 py-3 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {schedules.length === 0 ? (
                <tr>
                  <td
                    colSpan={6}
                    className="px-4 py-8 text-center text-text-muted"
                  >
                    No scheduled scans configured
                  </td>
                </tr>
              ) : (
                schedules.map((s) => (
                  <tr
                    key={s.id}
                    className="bg-bg-secondary transition-colors hover:bg-bg-tertiary"
                  >
                    <td className="px-4 py-2.5">
                      <span
                        className={`flex items-center gap-1.5 text-xs font-medium ${
                          s.enabled ? "text-neon-green" : "text-text-muted"
                        }`}
                      >
                        <span
                          className={`h-2 w-2 rounded-full ${
                            s.enabled
                              ? "bg-neon-green animate-pulse"
                              : "bg-text-muted"
                          }`}
                        />
                        {s.enabled ? "Active" : "Disabled"}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 font-mono text-xs text-text-primary">
                      {s.cron_expression}
                    </td>
                    <td className="px-4 py-2.5 text-xs text-text-secondary">
                      {s.playbook}
                    </td>
                    <td className="px-4 py-2.5 font-mono text-xs text-text-muted">
                      {s.last_run
                        ? new Date(s.last_run).toLocaleString()
                        : "Never"}
                    </td>
                    <td className="px-4 py-2.5 font-mono text-xs text-text-muted">
                      {s.next_run
                        ? new Date(s.next_run).toLocaleString()
                        : "\u2014"}
                    </td>
                    <td className="px-4 py-2.5">
                      <div className="flex items-center gap-1">
                        <button
                          onClick={() => handleToggle(s)}
                          className={`rounded p-1 transition-colors ${
                            s.enabled
                              ? "text-neon-green hover:bg-neon-green/10"
                              : "text-text-muted hover:bg-bg-surface"
                          }`}
                          title={s.enabled ? "Disable" : "Enable"}
                        >
                          {s.enabled ? (
                            <Power className="h-3.5 w-3.5" />
                          ) : (
                            <PowerOff className="h-3.5 w-3.5" />
                          )}
                        </button>
                        <button
                          onClick={() => handleDelete(s.id)}
                          className="rounded p-1 text-text-muted transition-colors hover:bg-danger/10 hover:text-danger"
                          title="Delete"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
