"use client";

import type { Finding } from "@/types/campaign";

interface FindingDetailProps {
  finding: Finding;
  onMarkFalsePositive?: () => void;
  onExport?: () => void;
}

export default function FindingDetail({ finding, onMarkFalsePositive, onExport }: FindingDetailProps) {
  const severityColors: Record<string, string> = {
    critical: "bg-red-500/20 text-red-400 border-red-500/30",
    high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
    medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
    info: "bg-gray-500/20 text-gray-400 border-gray-500/30",
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold text-text-primary">{finding.title}</h1>
          <div className="flex items-center gap-3 mt-2">
            <span
              className={`px-3 py-1 rounded-full text-xs font-medium border ${
                severityColors[finding.severity] || severityColors.info
              }`}
            >
              {finding.severity.toUpperCase()}
            </span>
            {finding.section_id && (
              <span className="text-xs text-text-secondary font-mono">{finding.section_id}</span>
            )}
            {finding.confirmed && (
              <span className="px-2 py-0.5 rounded text-xs bg-green-500/20 text-green-400">
                Confirmed
              </span>
            )}
            {finding.false_positive && (
              <span className="px-2 py-0.5 rounded text-xs bg-red-500/20 text-red-400">
                False Positive
              </span>
            )}
          </div>
        </div>
        <div className="flex gap-2">
          {onMarkFalsePositive && (
            <button
              onClick={onMarkFalsePositive}
              className="px-3 py-1.5 rounded text-xs font-medium bg-bg-void border border-border text-text-secondary hover:text-text-primary"
            >
              Mark False Positive
            </button>
          )}
          {onExport && (
            <button
              onClick={onExport}
              className="px-3 py-1.5 rounded text-xs font-medium bg-accent-primary text-white hover:bg-accent-primary/90"
            >
              Export
            </button>
          )}
        </div>
      </div>

      {/* Metadata */}
      <div className="grid grid-cols-2 gap-4 rounded-lg border border-border p-4 bg-bg-surface">
        <div>
          <div className="text-xs text-text-secondary">Target</div>
          <div className="text-sm text-text-primary">{finding.target_domain || finding.target_id}</div>
        </div>
        <div>
          <div className="text-xs text-text-secondary">Worker</div>
          <div className="text-sm text-text-primary">{finding.worker_type || "—"}</div>
        </div>
        <div>
          <div className="text-xs text-text-secondary">Stage</div>
          <div className="text-sm text-text-primary">{finding.stage_name || "—"}</div>
        </div>
        <div>
          <div className="text-xs text-text-secondary">Tool</div>
          <div className="text-sm text-text-primary">{finding.source_tool || "—"}</div>
        </div>
        <div>
          <div className="text-xs text-text-secondary">Vulnerability Type</div>
          <div className="text-sm text-text-primary">{finding.vuln_type}</div>
        </div>
        <div>
          <div className="text-xs text-text-secondary">Created</div>
          <div className="text-sm text-text-primary">
            {new Date(finding.created_at).toLocaleString()}
          </div>
        </div>
      </div>

      {/* Description */}
      {finding.description && (
        <div className="rounded-lg border border-border p-4 bg-bg-surface">
          <h2 className="text-sm font-semibold text-text-primary mb-2">Description</h2>
          <p className="text-sm text-text-secondary whitespace-pre-wrap">{finding.description}</p>
        </div>
      )}

      {/* Evidence */}
      {finding.evidence && (
        <div className="rounded-lg border border-border p-4 bg-bg-surface">
          <h2 className="text-sm font-semibold text-text-primary mb-2">Evidence</h2>
          <pre className="text-xs text-text-secondary bg-bg-void p-3 rounded overflow-x-auto">
            {JSON.stringify(finding.evidence, null, 2)}
          </pre>
        </div>
      )}

      {/* Remediation */}
      {finding.remediation && (
        <div className="rounded-lg border border-border p-4 bg-bg-surface">
          <h2 className="text-sm font-semibold text-text-primary mb-2">Remediation</h2>
          <p className="text-sm text-text-secondary whitespace-pre-wrap">{finding.remediation}</p>
        </div>
      )}
    </div>
  );
}
