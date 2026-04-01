"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import ReportList from "@/components/reports/ReportList";
import { toast } from "sonner";

interface Report {
  id: string;
  title: string;
  severity: string;
  target_domain: string;
  type: "individual" | "chain";
  created_at: string;
}

export default function ReportsPage() {
  const params = useParams();
  const router = useRouter();
  const campaignId = params.id as string;
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchReports = async () => {
      try {
        const res = await fetch(`/api/campaigns/${campaignId}/reports`);
        if (res.ok) {
          const data = await res.json();
          setReports(data);
        }
      } catch {
        // ignore
      } finally {
        setLoading(false);
      }
    };
    fetchReports();
  }, [campaignId]);

  const handleView = (id: string) => {
    router.push(`/campaign/${campaignId}/reports/${id}`);
  };

  const handleDownload = async (id: string) => {
    try {
      const res = await fetch(`/api/campaigns/${campaignId}/reports/${id}/download`);
      if (res.ok) {
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `report-${id}.md`;
        a.click();
        URL.revokeObjectURL(url);
        toast.success("Report downloaded");
      }
    } catch {
      toast.error("Failed to download report");
    }
  };

  const handleCopy = async (id: string) => {
    try {
      const report = reports.find((r) => r.id === id);
      if (report) {
        await navigator.clipboard.writeText(report.title);
        toast.success("Copied to clipboard");
      }
    } catch {
      toast.error("Failed to copy");
    }
  };

  if (loading) {
    return <div className="flex items-center justify-center h-64 text-text-secondary">Loading...</div>;
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-text-primary">Reports</h1>
        <p className="text-sm text-text-secondary mt-1">
          {reports.length} reports generated
        </p>
      </div>

      <div className="rounded-lg border border-border p-6 bg-bg-surface">
        <ReportList
          reports={reports}
          campaignId={campaignId}
          onView={handleView}
          onDownload={handleDownload}
          onCopy={handleCopy}
        />
      </div>
    </div>
  );
}
