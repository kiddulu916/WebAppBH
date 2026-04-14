"use client";

import { useEffect, useState, useMemo } from "react";
import {
  Brain,
  ArrowUpDown,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  ChevronDown,
  ChevronUp,
} from "lucide-react";
import { useCampaignStore } from "@/stores/campaign";
import { api } from "@/lib/api";
import type { InsightRow } from "@/lib/api";

const SEV_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

const SEV_COLORS: Record<string, string> = {
  critical: "text-sev-critical",
  high: "text-sev-high",
  medium: "text-sev-medium",
  low: "text-sev-low",
  info: "text-sev-info",
};

const SEV_BG: Record<string, string> = {
  critical: "bg-sev-critical/10",
  high: "bg-sev-high/10",
  medium: "bg-neon-orange-glow",
  low: "bg-neon-blue-glow",
  info: "bg-bg-tertiary",
};

type SortKey = "confidence" | "severity" | "bounty" | "report_readiness" | "false_positive";

function confidenceBar(value: number) {
  const pct = Math.round(value * 100);
  const color =
    value >= 0.8 ? "bg-neon-green" : value >= 0.5 ? "bg-neon-orange" : "bg-danger";
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-16 rounded-full bg-bg-tertiary overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-[10px] font-mono text-text-muted">{pct}%</span>
    </div>
  );
}

function InsightCard({ row, expanded, onToggle }: { row: InsightRow; expanded: boolean; onToggle: () => void }) {
  const sev = (row.severity_assessment || row.vulnerability_severity || "info").toLowerCase();

  return (
    <div className={`rounded-lg border border-border bg-bg-secondary transition-all ${expanded ? "ring-1 ring-border-accent" : ""}`}>
      {/* Header row */}
      <button
        onClick={onToggle}
        className="flex w-full items-center gap-3 px-4 py-3 text-left"
      >
        {/* Severity badge */}
        <span className={`shrink-0 rounded px-2 py-0.5 text-[10px] font-bold uppercase ${SEV_COLORS[sev]} ${SEV_BG[sev]}`}>
          {sev}
        </span>

        {/* Title */}
        <span className="flex-1 truncate text-sm text-text-primary">
          {row.vulnerability_title}
        </span>

        {/* Quick stats */}
        <div className="hidden md:flex items-center gap-4 text-[10px] text-text-muted shrink-0">
          <span title="Confidence">{confidenceBar(row.confidence)}</span>
          <span title="False positive likelihood" className="flex items-center gap-1">
            {row.false_positive_likelihood < 0.3 ? (
              <CheckCircle2 className="h-3 w-3 text-neon-green" />
            ) : row.false_positive_likelihood < 0.7 ? (
              <AlertTriangle className="h-3 w-3 text-warning" />
            ) : (
              <XCircle className="h-3 w-3 text-danger" />
            )}
            FP {Math.round(row.false_positive_likelihood * 100)}%
          </span>
          {row.bounty_estimate && (
            <span className="font-mono text-neon-green">
              ${row.bounty_estimate.low}-{row.bounty_estimate.high}
            </span>
          )}
          <span title="Report readiness" className="font-mono">
            RR {Math.round(row.report_readiness_score * 100)}%
          </span>
        </div>

        {expanded ? <ChevronUp className="h-4 w-4 text-text-muted" /> : <ChevronDown className="h-4 w-4 text-text-muted" />}
      </button>

      {/* Expanded detail */}
      {expanded && (
        <div className="border-t border-border px-4 py-3 space-y-3 animate-fade-in">
          {/* Grid of insight dimensions */}
          <div className="grid grid-cols-2 lg:grid-cols-3 gap-3">
            {row.exploitability && (
              <div>
                <span className="section-label">Exploitability</span>
                <p className="mt-1 text-xs text-text-secondary">{row.exploitability}</p>
              </div>
            )}
            {row.next_steps && (
              <div>
                <span className="section-label">Next Steps</span>
                <p className="mt-1 text-xs text-text-secondary">{row.next_steps}</p>
              </div>
            )}
            {row.owasp_cwe && (
              <div>
                <span className="section-label">Classification</span>
                <p className="mt-1 text-xs text-text-secondary">
                  {row.owasp_cwe.owasp} / CWE-{row.owasp_cwe.cwe_id}: {row.owasp_cwe.cwe_name}
                </p>
              </div>
            )}
            {row.asset_criticality && (
              <div>
                <span className="section-label">Asset Criticality</span>
                <p className={`mt-1 text-xs font-semibold uppercase ${SEV_COLORS[row.asset_criticality.toLowerCase()] || "text-text-secondary"}`}>
                  {row.asset_criticality}
                </p>
              </div>
            )}
            {row.chain_hypotheses && row.chain_hypotheses.length > 0 && (
              <div className="col-span-2">
                <span className="section-label">Chain Hypotheses</span>
                <ul className="mt-1 list-disc list-inside text-xs text-text-secondary space-y-0.5">
                  {row.chain_hypotheses.map((ch, i) => (
                    <li key={i}>Vuln #{ch.with_vuln_id}: {ch.description}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>

          {/* Metrics row */}
          <div className="flex flex-wrap gap-4 border-t border-border pt-2 text-[10px] text-text-muted">
            <span>Duplicate risk: {Math.round(row.duplicate_likelihood * 100)}%</span>
            <span>Model confidence: {Math.round(row.confidence * 100)}%</span>
            <span>Analyzed: {new Date(row.created_at).toLocaleString()}</span>
          </div>
        </div>
      )}
    </div>
  );
}

export default function TriagePage() {
  const activeTarget = useCampaignStore((s) => s.activeTarget);
  const [insights, setInsights] = useState<InsightRow[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sortKey, setSortKey] = useState<SortKey>("confidence");
  const [expandedId, setExpandedId] = useState<number | null>(null);

  useEffect(() => {
    if (!activeTarget) return;
    setLoading(true);
    setError(null);
    api
      .getInsights(activeTarget.id)
      .then((res) => setInsights(res.insights))
      .catch((e) => setError(e instanceof Error ? e.message : "Failed to load insights"))
      .finally(() => setLoading(false));
  }, [activeTarget]);

  const sorted = useMemo(() => {
    const copy = [...insights];
    switch (sortKey) {
      case "confidence":
        return copy.sort((a, b) => b.confidence - a.confidence);
      case "severity":
        return copy.sort((a, b) => {
          const sa = SEV_ORDER[(a.severity_assessment || "info").toLowerCase()] ?? 5;
          const sb = SEV_ORDER[(b.severity_assessment || "info").toLowerCase()] ?? 5;
          return sa - sb || b.confidence - a.confidence;
        });
      case "bounty":
        return copy.sort((a, b) => {
          const ba = a.bounty_estimate?.high ?? 0;
          const bb = b.bounty_estimate?.high ?? 0;
          return bb - ba;
        });
      case "report_readiness":
        return copy.sort((a, b) => b.report_readiness_score - a.report_readiness_score);
      case "false_positive":
        return copy.sort((a, b) => a.false_positive_likelihood - b.false_positive_likelihood);
      default:
        return copy;
    }
  }, [insights, sortKey]);

  // Summary stats
  const stats = useMemo(() => {
    const total = insights.length;
    const highConf = insights.filter((i) => i.confidence >= 0.8).length;
    const likelyReal = insights.filter((i) => i.false_positive_likelihood < 0.3).length;
    const totalBounty = insights.reduce((acc, i) => acc + (i.bounty_estimate?.high ?? 0), 0);
    return { total, highConf, likelyReal, totalBounty };
  }, [insights]);

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-bold text-text-primary">
            <Brain className="h-5 w-5 text-neon-orange" />
            AI Triage
          </h1>
          <p className="mt-1 text-sm text-text-secondary">
            LLM-powered vulnerability analysis and prioritization
          </p>
        </div>
        {activeTarget && (
          <span className="rounded-md bg-bg-secondary px-3 py-1.5 font-mono text-sm text-neon-orange">
            {activeTarget.base_domain}
          </span>
        )}
      </div>

      {/* Summary cards */}
      {insights.length > 0 && (
        <div className="grid grid-cols-4 gap-3">
          <div className="rounded-lg border border-border bg-bg-secondary p-3 text-center">
            <div className="text-2xl font-bold text-text-primary">{stats.total}</div>
            <div className="section-label mt-1">Analyzed</div>
          </div>
          <div className="rounded-lg border border-border bg-bg-secondary p-3 text-center">
            <div className="text-2xl font-bold text-neon-green">{stats.highConf}</div>
            <div className="section-label mt-1">High Confidence</div>
          </div>
          <div className="rounded-lg border border-border bg-bg-secondary p-3 text-center">
            <div className="text-2xl font-bold text-neon-blue">{stats.likelyReal}</div>
            <div className="section-label mt-1">Likely Real</div>
          </div>
          <div className="rounded-lg border border-border bg-bg-secondary p-3 text-center">
            <div className="text-2xl font-bold font-mono text-neon-green">
              ${stats.totalBounty.toLocaleString()}
            </div>
            <div className="section-label mt-1">Est. Max Bounty</div>
          </div>
        </div>
      )}

      {/* Sort controls */}
      {insights.length > 0 && (
        <div className="flex items-center gap-2">
          <ArrowUpDown className="h-3.5 w-3.5 text-text-muted" />
          <span className="text-[10px] text-text-muted uppercase tracking-wide">Sort by:</span>
          {(
            [
              ["confidence", "Confidence"],
              ["severity", "Severity"],
              ["bounty", "Bounty Est."],
              ["report_readiness", "Report Ready"],
              ["false_positive", "Least FP"],
            ] as [SortKey, string][]
          ).map(([key, label]) => (
            <button
              key={key}
              onClick={() => setSortKey(key)}
              className={`rounded px-2 py-0.5 text-[10px] transition-colors ${
                sortKey === key
                  ? "bg-neon-orange/10 text-neon-orange font-semibold"
                  : "text-text-muted hover:text-text-secondary hover:bg-bg-surface"
              }`}
            >
              {label}
            </button>
          ))}
        </div>
      )}

      {/* Content */}
      {!activeTarget && (
        <div className="rounded-lg border border-dashed border-border-accent bg-bg-tertiary p-8 text-center text-sm text-text-muted">
          Select a target to view AI triage results
        </div>
      )}

      {loading && (
        <div className="text-center text-sm text-text-muted py-8">Loading insights...</div>
      )}

      {error && (
        <div className="rounded-lg border border-danger/30 bg-danger/10 p-4 text-sm text-danger">
          {error}
        </div>
      )}

      {activeTarget && !loading && !error && insights.length === 0 && (
        <div className="rounded-lg border border-dashed border-border-accent bg-bg-tertiary p-8 text-center text-sm text-text-muted">
          No AI insights yet. Run the reasoning worker to analyze findings.
        </div>
      )}

      {/* Insight cards */}
      <div className="space-y-2">
        {sorted.map((row) => (
          <InsightCard
            key={row.id}
            row={row}
            expanded={expandedId === row.id}
            onToggle={() => setExpandedId(expandedId === row.id ? null : row.id)}
          />
        ))}
      </div>
    </div>
  );
}
