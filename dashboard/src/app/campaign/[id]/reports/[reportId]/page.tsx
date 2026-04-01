"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import ReportViewer from "@/components/reports/ReportViewer";

export default function ReportDetailPage() {
  const params = useParams();
  const campaignId = params.id as string;
  const reportId = params.reportId as string;
  const [content, setContent] = useState("");
  const [title, setTitle] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchReport = async () => {
      try {
        const res = await fetch(`/api/campaigns/${campaignId}/reports/${reportId}`);
        if (res.ok) {
          const data = await res.json();
          setContent(data.content);
          setTitle(data.title);
        }
      } catch {
        // ignore
      } finally {
        setLoading(false);
      }
    };
    fetchReport();
  }, [campaignId, reportId]);

  if (loading) {
    return <div className="flex items-center justify-center h-64 text-text-secondary">Loading...</div>;
  }

  return <ReportViewer reportId={reportId} content={content} title={title} />;
}
