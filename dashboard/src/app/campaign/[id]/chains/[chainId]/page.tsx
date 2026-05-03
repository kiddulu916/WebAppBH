"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import ChainDetail from "@/components/chains/ChainDetail";
import type { ChainFindingView, Finding, VulnSeverity } from "@/types/schema";
import { api } from "@/lib/api";

export default function ChainDetailPage() {
  const params = useParams();
  const campaignId = params.id as string;
  const chainId = params.chainId as string;
  const [chain, setChain] = useState<ChainFindingView | null>(null);
  const [linkedFindings, setLinkedFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchChain = async () => {
      try {
        // Find the chain by iterating targets and their attack paths
        const targetsRes = await api.getTargets();
        let foundChain: ChainFindingView | null = null;
        const foundFindings: Finding[] = [];

        for (const target of targetsRes.targets) {
          try {
            const pathsRes = await api.getAttackPaths(target.id);
            for (const path of pathsRes.paths) {
              if (String(path.id) === chainId) {
                foundChain = {
                  id: path.id,
                  target_id: target.id,
                  chain_description: path.description,
                  severity: path.severity,
                  total_impact: null,
                  linked_vulnerability_ids: path.steps.map(s => s.vuln_id),
                  created_at: new Date().toISOString(),
                };

                // Fetch linked vulnerabilities as findings
                for (const step of path.steps) {
                  try {
                    const v = await api.getVulnerability(step.vuln_id);
                    foundFindings.push({
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
                    // vulnerability may not exist
                  }
                }
                break;
              }
            }
            if (foundChain) break;
          } catch {
            // target may not have attack paths
          }
        }

        setChain(foundChain);
        setLinkedFindings(foundFindings);
      } catch {
        // ignore
      } finally {
        setLoading(false);
      }
    };
    fetchChain();
  }, [campaignId, chainId]);

  if (loading) {
    return <div className="flex items-center justify-center h-64 text-text-secondary">Loading...</div>;
  }

  if (!chain) {
    return <div className="text-center py-8 text-text-secondary">Chain not found</div>;
  }

  return <ChainDetail chain={chain} linkedFindings={linkedFindings} />;
}
