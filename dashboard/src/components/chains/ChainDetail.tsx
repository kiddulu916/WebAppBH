"use client";

import type { ChainFindingView, Finding } from "@/types/campaign";

interface ChainDetailProps {
  chain: ChainFindingView;
  linkedFindings: Finding[];
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  info: "bg-gray-500/20 text-gray-400 border-gray-500/30",
};

export default function ChainDetail({ chain, linkedFindings }: ChainDetailProps) {
  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-text-primary">Chain Finding</h1>
        <div className="flex items-center gap-3 mt-2">
          <span
            className={`px-3 py-1 rounded-full text-xs font-medium border ${
              SEVERITY_COLORS[chain.severity] || SEVERITY_COLORS.info
            }`}
          >
            {chain.severity.toUpperCase()}
          </span>
          {chain.total_impact && (
            <span className="text-xs text-text-secondary">Impact: {chain.total_impact}</span>
          )}
        </div>
      </div>

      {/* Description */}
      <div className="rounded-lg border border-border p-4 bg-bg-surface">
        <h2 className="text-sm font-semibold text-text-primary mb-2">Chain Description</h2>
        <p className="text-sm text-text-secondary whitespace-pre-wrap">{chain.chain_description}</p>
      </div>

      {/* Linked Vulnerabilities */}
      <div className="rounded-lg border border-border p-4 bg-bg-surface">
        <h2 className="text-sm font-semibold text-text-primary mb-4">
          Linked Vulnerabilities ({linkedFindings.length})
        </h2>
        <div className="space-y-3">
          {linkedFindings.map((finding, idx) => (
            <div
              key={finding.id}
              className="flex items-start gap-3 p-3 rounded bg-bg-void border border-border"
            >
              <div className="flex-shrink-0 w-6 h-6 rounded-full bg-accent-primary/20 text-accent-primary flex items-center justify-center text-xs font-medium">
                {idx + 1}
              </div>
              <div className="flex-1">
                <div className="flex items-center gap-2">
                  <span className="font-medium text-text-primary text-sm">{finding.title}</span>
                  <span
                    className={`px-2 py-0.5 rounded text-xs ${
                      SEVERITY_COLORS[finding.severity] || SEVERITY_COLORS.info
                    }`}
                  >
                    {finding.severity}
                  </span>
                </div>
                <div className="text-xs text-text-secondary mt-1">
                  {finding.source_tool} • {finding.section_id || "N/A"}
                </div>
                {finding.description && (
                  <p className="text-xs text-text-secondary mt-2 line-clamp-2">
                    {finding.description}
                  </p>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Metadata */}
      <div className="text-xs text-text-secondary">
        Created: {new Date(chain.created_at).toLocaleString()}
      </div>
    </div>
  );
}
