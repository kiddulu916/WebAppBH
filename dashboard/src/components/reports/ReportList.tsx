import { useState } from "react";
import Link from "next/link";

interface Report {
  id: string;
  title: string;
  severity: string;
  target_domain: string;
  type: "individual" | "chain";
  created_at: string;
}

interface ReportListProps {
  reports: Report[];
  campaignId: string;
  onView: (id: string) => void;
  onDownload: (id: string) => void;
  onCopy: (id: string) => void;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "text-sev-critical",
  high: "text-sev-high",
  medium: "text-sev-medium",
  low: "text-sev-low",
  info: "text-text-muted",
};

export default function ReportList({ reports, campaignId, onView, onDownload, onCopy }: ReportListProps) {
  const [activeTab, setActiveTab] = useState<"individual" | "chain">("individual");

  const filtered = reports.filter((r) => r.type === activeTab);

  return (
    <div className="space-y-4">
      {/* Tabs */}
      <div className="flex gap-2 border-b border-border">
        <button
          onClick={() => setActiveTab("individual")}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
            activeTab === "individual"
              ? "border-accent text-accent"
              : "border-transparent text-text-secondary hover:text-text-primary"
          }`}
        >
          Individual Reports
        </button>
        <button
          onClick={() => setActiveTab("chain")}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
            activeTab === "chain"
              ? "border-accent text-accent"
              : "border-transparent text-text-secondary hover:text-text-primary"
          }`}
        >
          Chain Reports
        </button>
      </div>

      {/* Export All */}
      <div className="flex justify-end">
        <Link
          href={`/api/campaigns/${campaignId}/reports/export`}
          className="px-3 py-1.5 rounded text-xs font-medium btn-launch"
        >
          Export All as ZIP
        </Link>
      </div>

      {/* Reports list */}
      {filtered.length === 0 ? (
        <div className="text-center py-8 text-text-secondary">No {activeTab} reports</div>
      ) : (
        <div className="space-y-2">
          {filtered.map((report) => (
            <div
              key={report.id}
              className="flex items-center justify-between p-4 rounded-lg border border-border bg-bg-surface"
            >
              <div className="flex-1">
                <Link
                  href={`/campaign/${campaignId}/reports/${report.id}`}
                  className="font-medium text-text-primary hover:text-accent"
                >
                  {report.title}
                </Link>
                <div className="text-xs text-text-secondary mt-1">
                  {report.target_domain} • {new Date(report.created_at).toLocaleDateString()}
                </div>
              </div>
              <div className="flex items-center gap-3">
                <span className={`text-xs font-medium capitalize ${SEVERITY_COLORS[report.severity] || SEVERITY_COLORS.info}`}>
                  {report.severity}
                </span>
                <button
                  onClick={() => onView(report.id)}
                  className="px-2 py-1 rounded text-xs bg-bg-void border border-border text-text-secondary hover:text-text-primary"
                >
                  View
                </button>
                <button
                  onClick={() => onDownload(report.id)}
                  className="px-2 py-1 rounded text-xs bg-bg-void border border-border text-text-secondary hover:text-text-primary"
                >
                  Download
                </button>
                <button
                  onClick={() => onCopy(report.id)}
                  className="px-2 py-1 rounded text-xs bg-bg-void border border-border text-text-secondary hover:text-text-primary"
                >
                  Copy
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
