"use client";

import { useState } from "react";
import { toast } from "sonner";

interface ReportViewerProps {
  reportId: string;
  content: string;
  title: string;
}

export default function ReportViewer({ content, title }: ReportViewerProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(content);
      setCopied(true);
      toast.success("Copied to clipboard");
      setTimeout(() => setCopied(false), 2000);
    } catch {
      toast.error("Failed to copy to clipboard");
    }
  };

  const handleDownload = () => {
    const blob = new Blob([content], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${title.replace(/[^a-z0-9]/gi, "-").toLowerCase()}.md`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success("Report downloaded");
  };

  return (
    <div className="space-y-4">
      {/* Actions */}
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-text-primary">{title}</h2>
        <div className="flex gap-2">
          <button
            onClick={handleCopy}
            className="px-3 py-1.5 rounded text-xs font-medium bg-bg-void border border-border text-text-secondary hover:text-text-primary"
          >
            {copied ? "Copied!" : "Copy to Clipboard"}
          </button>
          <button
            onClick={handleDownload}
            className="px-3 py-1.5 rounded text-xs font-medium bg-accent-primary text-white hover:bg-accent-primary/90"
          >
            Download .md
          </button>
        </div>
      </div>

      {/* Report content */}
      <div className="rounded-lg border border-border bg-bg-surface p-6">
        <div className="prose prose-sm prose-invert max-w-none">
          <pre className="whitespace-pre-wrap text-sm text-text-secondary font-mono">
            {content}
          </pre>
        </div>
      </div>
    </div>
  );
}
