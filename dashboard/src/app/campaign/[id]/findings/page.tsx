"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import FindingsTable from "@/components/findings/FindingsTable";
import type { Finding } from "@/types/campaign";

export default function FindingsPage() {
  const params = useParams();
  const campaignId = params.id as string;
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchFindings = async () => {
      try {
        const res = await fetch(`/api/campaigns/${campaignId}/findings`);
        if (res.ok) {
          const data = await res.json();
          setFindings(data);
        }
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
