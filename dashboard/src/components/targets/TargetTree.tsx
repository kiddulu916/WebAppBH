import Link from "next/link";
import type { TargetNode } from "@/types/schema";

interface TargetTreeProps {
  targets: TargetNode[];
  campaignId: string;
}

export default function TargetTree({ targets, campaignId }: TargetTreeProps) {
  const renderTarget = (target: TargetNode, depth: number) => {
    const statusColor =
      target.status === "complete"
        ? "text-neon-green"
        : target.status === "running"
          ? "text-neon-orange"
          : target.status === "queued"
            ? "text-neon-blue"
            : "text-text-muted";

    const statusIcon =
      target.status === "complete"
        ? "✓"
        : target.status === "running"
          ? "⟳"
          : target.status === "queued"
            ? "◷"
            : "○";

    return (
      <div key={target.id} style={{ marginLeft: depth > 0 ? `${depth * 24}px` : 0 }}>
        <Link
          href={`/campaign/${campaignId}/targets/${target.id}`}
          className="flex items-center gap-3 p-3 rounded-lg border border-border bg-bg-surface hover:bg-bg-surface/80 transition-colors mb-2"
        >
          <span className={`text-lg ${statusColor}`}>{statusIcon}</span>
          <div className="flex-1">
            <div className="font-medium text-text-primary">{target.domain}</div>
            <div className="text-xs text-text-secondary">
              Priority: P:{target.priority} | Type: {target.target_type}
              {target.wildcard && ` | Wildcard (${target.wildcard_count} subdomains)`}
            </div>
          </div>
          <div className="text-right">
            <div className="text-sm font-semibold text-text-primary">
              {target.vulnerability_count}
            </div>
            <div className="text-xs text-text-secondary">vulns</div>
          </div>
        </Link>

        {target.children?.map((child) => renderTarget(child, depth + 1))}
      </div>
    );
  };

  return <div className="space-y-1">{targets.map((t) => renderTarget(t, 0))}</div>;
}
