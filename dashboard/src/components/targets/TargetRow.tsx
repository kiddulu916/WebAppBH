import Link from "next/link";
import type { TargetNode } from "@/types/campaign";

interface TargetRowProps {
  target: TargetNode;
  campaignId: string;
}

export default function TargetRow({ target, campaignId }: TargetRowProps) {
  const statusColor =
    target.status === "complete"
      ? "text-green-400"
      : target.status === "running"
        ? "text-amber-400"
        : target.status === "queued"
          ? "text-blue-400"
          : "text-gray-400";

  const statusIcon =
    target.status === "complete"
      ? "✓"
      : target.status === "running"
        ? "⟳"
        : target.status === "queued"
          ? "◷"
          : "○";

  return (
    <Link
      href={`/campaign/${campaignId}/targets/${target.id}`}
      className="flex items-center gap-3 p-3 rounded-lg border border-border bg-bg-surface hover:bg-bg-surface/80 transition-colors"
    >
      <span className={`text-lg ${statusColor}`}>{statusIcon}</span>
      <div className="flex-1">
        <div className="font-medium text-text-primary">{target.domain}</div>
        <div className="text-xs text-text-secondary">
          P:{target.priority} | {target.target_type}
          {target.wildcard && ` | * (${target.wildcard_count})`}
        </div>
      </div>
      <div className="text-right">
        <div className="text-sm font-semibold text-text-primary">
          {target.vulnerability_count}
        </div>
        <div className="text-xs text-text-secondary">vulns</div>
      </div>
    </Link>
  );
}
