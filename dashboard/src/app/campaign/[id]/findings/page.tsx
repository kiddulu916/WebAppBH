"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import FindingsTable from "@/components/findings/FindingsTable";
import type { Finding } from "@/types/schema";
import type { VulnSeverity } from "@/types/schema";
import { api } from "@/lib/api";

export default function FindingsPage() {
  const params = useParams();
  const campaignId = params.id as string;
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchFindings = async () => {
      try {
        const targetsRes = await api.getTargets();
        const allFindings: Finding[] = [];
        for (const target of targetsRes.targets) {
          try {
            const vulnRes = await api.getVulnerabilities(target.id);
            for (const v of vulnRes.vulnerabilities) {
              allFindings.push({
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
                target_domain: v.asset_value || undefined,
              });
            }
          } catch {
            // target may not have vulnerabilities
          }
        }
        setFindings(allFindings);
      } catch {
        // ignore
      } finally {
        setLoading(false);
      }
    };
    fetchFindings();
  }, [campaignId]);

  if (loading) {
    return <div className="flex items-center justify-center h-64 text-text-secondary">Loading...</div>;
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-text-primary">Findings</h1>
        <p className="text-sm text-text-secondary mt-1">
          {findings.length} vulnerabilities discovered
        </p>
      </div>

      <FindingsTable findings={findings} campaignId={campaignId} />
    </div>
  );
}
