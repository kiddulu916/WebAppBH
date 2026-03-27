"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { DollarSign, Loader2, TrendingUp, CheckCircle2, Clock, Send } from "lucide-react";
import { api, type BountyRow } from "@/lib/api";
import { useCampaignStore } from "@/stores/campaign";

const STATUS_COLORS: Record<string, string> = {
  submitted: "bg-neon-blue/15 text-neon-blue border-neon-blue/25",
  accepted: "bg-neon-green/15 text-neon-green border-neon-green/25",
  paid: "bg-neon-orange/15 text-neon-orange border-neon-orange/25",
  rejected: "bg-danger/15 text-danger border-danger/25",
  duplicate: "bg-bg-surface text-text-muted border-border",
};

export default function BountiesPage() {
  const router = useRouter();
  const activeTarget = useCampaignStore((s) => s.activeTarget);
  const [bounties, setBounties] = useState<BountyRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState<{
    total_submitted: number;
    total_accepted: number;
    total_paid: number;
    total_payout: number;
    by_platform: Record<string, number>;
    by_target: Record<string, number>;
  } | null>(null);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [editStatus, setEditStatus] = useState("");
  const [editPayout, setEditPayout] = useState("");

  useEffect(() => {
    if (!activeTarget) {
      router.push("/");
      return;
    }
    let cancelled = false;

    Promise.all([
      api.getBounties(activeTarget.id),
      api.getBountyStats(),
    ])
      .then(([bRes, sRes]) => {
        if (!cancelled) {
          setBounties(bRes ?? []);
          setStats(sRes ?? null);
        }
      })
      .catch(() => {})
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => { cancelled = true; };
  }, [activeTarget, router]);

  const handleUpdate = async (id: number) => {
    try {
      const data: { status?: string; actual_payout?: number } = {};
      if (editStatus) data.status = editStatus;
      if (editPayout) data.actual_payout = parseFloat(editPayout);
      const updated = await api.updateBounty(id, data);
      setBounties((prev) => prev.map((b) => (b.id === id ? updated : b)));
      setEditingId(null);
      setEditStatus("");
      setEditPayout("");
    } catch {
      // toast shown by api.request()
    }
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
      <div>
        <h1 className="flex items-center gap-2 text-2xl font-bold text-text-primary">
          <DollarSign className="h-5 w-5 text-neon-orange" />
          Bounty Tracker
        </h1>
        <p className="mt-1 text-sm text-text-secondary">
          Track submissions, payouts, and ROI
        </p>
      </div>

      {/* Stats cards */}
      {stats && (
        <div className="grid grid-cols-4 gap-3">
          <div className="rounded-lg border border-border bg-bg-secondary p-3">
            <div className="flex items-center gap-2 text-text-muted">
              <Send className="h-3.5 w-3.5" />
              <span className="text-[10px]">SUBMITTED</span>
            </div>
            <div className="mt-1 text-xl font-bold font-mono text-text-primary">
              {stats.total_submitted}
            </div>
          </div>
          <div className="rounded-lg border border-border bg-bg-secondary p-3">
            <div className="flex items-center gap-2 text-text-muted">
              <CheckCircle2 className="h-3.5 w-3.5" />
              <span className="text-[10px]">ACCEPTED</span>
            </div>
            <div className="mt-1 text-xl font-bold font-mono text-neon-green">
              {stats.total_accepted}
            </div>
          </div>
          <div className="rounded-lg border border-border bg-bg-secondary p-3">
            <div className="flex items-center gap-2 text-text-muted">
              <Clock className="h-3.5 w-3.5" />
              <span className="text-[10px]">PAID COUNT</span>
            </div>
            <div className="mt-1 text-xl font-bold font-mono text-neon-blue">
              {stats.total_paid}
            </div>
          </div>
          <div className="rounded-lg border border-border bg-bg-secondary p-3">
            <div className="flex items-center gap-2 text-text-muted">
              <TrendingUp className="h-3.5 w-3.5" />
              <span className="text-[10px]">TOTAL PAYOUT</span>
            </div>
            <div className="mt-1 text-xl font-bold font-mono text-neon-orange">
              ${stats.total_payout?.toLocaleString() ?? "0"}
            </div>
          </div>
        </div>
      )}

      {/* ROI bar chart */}
      {bounties.length > 0 && (
        <div className="rounded-lg border border-border bg-bg-secondary p-4">
          <span className="section-label mb-3 block">PAYOUT DISTRIBUTION</span>
          <div className="space-y-2">
            {Object.entries(
              bounties.reduce<Record<string, number>>((acc, b) => {
                const key = b.status;
                acc[key] = (acc[key] ?? 0) + (b.actual_payout ?? b.expected_payout ?? 0);
                return acc;
              }, {}),
            ).map(([status, amount]) => {
              const maxAmount = Math.max(
                ...Object.values(
                  bounties.reduce<Record<string, number>>((acc, b) => {
                    acc[b.status] = (acc[b.status] ?? 0) + (b.actual_payout ?? b.expected_payout ?? 0);
                    return acc;
                  }, {}),
                ),
                1,
              );
              return (
                <div key={status} className="flex items-center gap-2">
                  <span className="w-20 text-right font-mono text-[10px] text-text-muted">
                    {status}
                  </span>
                  <div className="flex-1 h-4 rounded bg-bg-void overflow-hidden">
                    <div
                      className="h-full rounded bg-neon-orange/60"
                      style={{ width: `${(amount / maxAmount) * 100}%` }}
                    />
                  </div>
                  <span className="w-16 font-mono text-[10px] text-text-muted">
                    ${amount.toLocaleString()}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Table */}
      {loading ? (
        <div className="flex h-32 items-center justify-center">
          <Loader2 className="h-5 w-5 animate-spin text-neon-orange" />
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border">
          <table data-testid="bounties-table" className="w-full text-left text-sm">
            <thead className="bg-bg-surface text-xs text-text-secondary">
              <tr>
                <th className="px-4 py-3 font-medium">ID</th>
                <th className="px-4 py-3 font-medium">Platform</th>
                <th className="px-4 py-3 font-medium">Status</th>
                <th className="px-4 py-3 font-medium">Expected</th>
                <th className="px-4 py-3 font-medium">Paid</th>
                <th className="px-4 py-3 font-medium">Submitted</th>
                <th className="px-4 py-3 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {bounties.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-4 py-8 text-center text-text-muted">
                    No bounty submissions yet
                  </td>
                </tr>
              ) : (
                bounties.map((b) => (
                  <tr key={b.id} data-testid={`bounty-row-${b.id}`} className="bg-bg-secondary transition-colors hover:bg-bg-tertiary">
                    <td className="px-4 py-2.5 font-mono text-xs text-text-muted">#{b.id}</td>
                    <td className="px-4 py-2.5 text-xs text-text-primary">{b.platform}</td>
                    <td className="px-4 py-2.5">
                      {editingId === b.id ? (
                        <select
                          value={editStatus || b.status}
                          onChange={(e) => setEditStatus(e.target.value)}
                          className="rounded border border-border bg-bg-void px-1.5 py-0.5 text-xs text-text-primary"
                        >
                          {["submitted", "accepted", "paid", "rejected", "duplicate"].map((s) => (
                            <option key={s} value={s}>{s}</option>
                          ))}
                        </select>
                      ) : (
                        <span data-testid={`bounty-status-${b.id}`} className={`rounded-md border px-2 py-0.5 text-xs font-medium ${STATUS_COLORS[b.status] ?? STATUS_COLORS.submitted}`}>
                          {b.status}
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-2.5 font-mono text-xs text-text-secondary">
                      {b.expected_payout != null ? `$${b.expected_payout}` : "\u2014"}
                    </td>
                    <td className="px-4 py-2.5 font-mono text-xs text-neon-green">
                      {editingId === b.id ? (
                        <input
                          type="number"
                          value={editPayout}
                          onChange={(e) => setEditPayout(e.target.value)}
                          placeholder={b.actual_payout?.toString() ?? "0"}
                          className="w-20 rounded border border-border bg-bg-void px-1.5 py-0.5 text-xs text-text-primary"
                        />
                      ) : (
                        b.actual_payout != null ? `$${b.actual_payout}` : "\u2014"
                      )}
                    </td>
                    <td className="px-4 py-2.5 font-mono text-xs text-text-muted">
                      {b.submission_url
                        ? b.submission_url
                        : "\u2014"}
                    </td>
                    <td className="px-4 py-2.5">
                      {editingId === b.id ? (
                        <div className="flex gap-1">
                          <button
                            onClick={() => handleUpdate(b.id)}
                            className="rounded bg-neon-green/15 px-2 py-0.5 text-[10px] text-neon-green hover:bg-neon-green/25"
                          >
                            Save
                          </button>
                          <button
                            onClick={() => { setEditingId(null); setEditStatus(""); setEditPayout(""); }}
                            className="rounded px-2 py-0.5 text-[10px] text-text-muted hover:text-text-primary"
                          >
                            Cancel
                          </button>
                        </div>
                      ) : (
                        <button
                          data-testid={`bounty-edit-${b.id}`}
                          onClick={() => setEditingId(b.id)}
                          className="rounded px-2 py-0.5 text-[10px] text-text-muted hover:bg-bg-surface hover:text-text-primary"
                        >
                          Edit
                        </button>
                      )}
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
