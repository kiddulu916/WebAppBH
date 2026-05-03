"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import ReportViewer from "@/components/reports/ReportViewer";
import { api } from "@/lib/api";

export default function ReportDetailPage() {
  const params = useParams();
  const reportId = params.reportId as string;
  const [content, setContent] = useState("");
  const [title, setTitle] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchReport = async () => {
      try {
        const data = await api.getReport(reportId);
        setContent(data.content);
        setTitle(data.title);
      } catch {
        // ignore — endpoint may not exist yet
      } finally {
        setLoading(false);
      }
    };
    fetchReport();
  }, [reportId]);

  if (loading) {
    return <div className="flex items-center justify-center h-64 text-text-secondary">Loading...</div>;
  }

  return <ReportViewer reportId={reportId} content={content} title={title} />;
}
