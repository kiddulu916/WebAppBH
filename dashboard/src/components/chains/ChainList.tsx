import Link from "next/link";
import type { ChainFindingView } from "@/types/schema";

interface ChainListProps {
  chains: ChainFindingView[];
  campaignId: string;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "text-sev-critical",
  high: "text-sev-high",
  medium: "text-sev-medium",
  low: "text-sev-low",
  info: "text-text-muted",
};

export default function ChainList({ chains, campaignId }: ChainListProps) {
  if (chains.length === 0) {
    return <div className="text-center py-8 text-text-secondary">No chain findings discovered</div>;
  }

  return (
    <div className="space-y-2">
      {chains.map((chain) => (
        <Link
          key={chain.id}
          href={`/campaign/${campaignId}/chains/${chain.id}`}
          className="block p-4 rounded-lg border border-border bg-bg-surface hover:bg-bg-surface/80 transition-colors"
        >
          <div className="flex items-center justify-between">
            <div className="flex-1">
              <div className="font-medium text-text-primary">{chain.chain_description}</div>
              <div className="text-xs text-text-secondary mt-1">
                {chain.linked_vulnerability_ids?.length || 0} linked vulnerabilities
              </div>
            </div>
            <div className="text-right">
              <div className={`text-sm font-semibold capitalize ${SEVERITY_COLORS[chain.severity] || SEVERITY_COLORS.info}`}>
                {chain.severity}
              </div>
              <div className="text-xs text-text-secondary">
                {new Date(chain.created_at).toLocaleDateString()}
              </div>
            </div>
          </div>
        </Link>
      ))}
    </div>
  );
}
