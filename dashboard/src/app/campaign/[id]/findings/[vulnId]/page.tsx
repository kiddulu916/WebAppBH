"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import FindingDetail from "@/components/findings/FindingDetail";
import type { Finding, VulnSeverity } from "@/types/schema";
import { api } from "@/lib/api";

export default function FindingDetailPage() {
  const params = useParams();
  const campaignId = params.id as string;
  const vulnId = params.vulnId as string;
  const [finding, setFinding] = useState<Finding | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchFinding = async () => {
      try {
        const v = await api.getVulnerability(Number(vulnId));
        setFinding({
          id: v.id,
          target_id: v.target_id,
          severity: v.severity as VulnSeverity,
          title: v.title,
          vuln_type: v.severity,
          section_id: null,
          worker_type: null,
          stage_name: null,
          source_tool: v.source_tool,
          confirmed: false,
          false_positive: false,
          description: v.description,
          evidence: null,
          remediation: null,
          created_at: v.created_at || "",
        });
      } catch {
        // ignore
      } finally {
        setLoading(false);
      }
    };
    fetchFinding();
  }, [campaignId, vulnId]);

  const handleMarkFalsePositive = async () => {
    if (!finding) return;
    try {
      await api.updateVulnerability(Number(vulnId), { false_positive: true });
      setFinding({ ...finding, false_positive: true });
    } catch {
      // ignore
    }
  };

  const handleExport = () => {
    if (!finding) return;
    const blob = new Blob([JSON.stringify(finding, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `finding-${vulnId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (loading) {
    return <div className="flex items-center justify-center h-64 text-text-secondary">Loading...</div>;
  }

  if (!finding) {
    return <div className="text-center py-8 text-text-secondary">Finding not found</div>;
  }

  return (
    <FindingDetail
      finding={finding}
      onMarkFalsePositive={handleMarkFalsePositive}
      onExport={handleExport}
    />
  );
}
