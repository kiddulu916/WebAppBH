"use client";

import { useState } from "react";
import { FileText, Copy, Check, Loader2 } from "lucide-react";
import { api } from "@/lib/api";

interface DraftReportButtonProps {
  vulnId: number;
}

export default function DraftReportButton({ vulnId }: DraftReportButtonProps) {
  const [draft, setDraft] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);
  const [platform, setPlatform] = useState<"hackerone" | "bugcrowd">("hackerone");

  async function generate() {
    setLoading(true);
    try {
      const res = await api.getDraftReport(vulnId, platform);
      setDraft(res.draft);
    } catch {
      // toast shown by api.request()
      setDraft("Error generating draft report.");
    } finally {
      setLoading(false);
    }
  }

  async function copyDraft() {
    if (!draft) return;
    await navigator.clipboard.writeText(draft);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <select
          value={platform}
          onChange={(e) => setPlatform(e.target.value as "hackerone" | "bugcrowd")}
          className="rounded border border-border bg-bg-secondary px-2 py-1 text-xs text-text-primary"
        >
          <option value="hackerone">HackerOne</option>
          <option value="bugcrowd">Bugcrowd</option>
        </select>
        <button
          onClick={generate}
          disabled={loading}
          className="flex items-center gap-1 rounded bg-accent px-3 py-1 text-xs font-medium text-white transition-colors hover:bg-accent/80 disabled:opacity-50"
        >
          {loading ? (
            <Loader2 className="h-3 w-3 animate-spin" />
          ) : (
            <FileText className="h-3 w-3" />
          )}
          Draft Report
        </button>
      </div>
      {draft && (
        <div className="relative rounded-lg border border-border bg-bg-secondary p-3">
          <button
            onClick={copyDraft}
            className="absolute right-2 top-2 rounded p-1 text-text-muted hover:text-accent"
          >
            {copied ? <Check className="h-3 w-3 text-neon-green" /> : <Copy className="h-3 w-3" />}
          </button>
          <pre className="max-h-80 overflow-auto whitespace-pre-wrap text-xs text-text-secondary">
            {draft}
          </pre>
        </div>
      )}
    </div>
  );
}
