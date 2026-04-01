"use client";

import { useState } from "react";
import Link from "next/link";
import { usePathname, useParams } from "next/navigation";
import ResourceIndicator from "@/components/resource/ResourceIndicator";
import ResourcePanel from "@/components/resource/ResourcePanel";
import LiveTerminal from "@/components/terminal/LiveTerminal";
import { useCampaignStore } from "@/stores/campaignStore";
import { usePipelineStore } from "@/stores/pipelineStore";
import type { TargetEvent } from "@/types/campaign";

const TABS = [
  { label: "Overview", href: "/overview" },
  { label: "Targets", href: "/targets" },
  { label: "Findings", href: "/findings" },
  { label: "Chains", href: "/chains" },
  { label: "Reports", href: "/reports" },
];

export default function CampaignLayout({ children }: { children: React.ReactNode }) {
  const params = useParams();
  const pathname = usePathname();
  const campaignId = params.id as string;
  const activeCampaign = useCampaignStore((s) => s.activeCampaign);
  const [showResourcePanel, setShowResourcePanel] = useState(false);
  const [terminalEvents, setTerminalEvents] = useState<TargetEvent[]>([]);

  const resourceStatus = usePipelineStore((s) => s.resourceStatus);

  const addTerminalEvent = (event: TargetEvent) => {
    setTerminalEvents((prev) => [...prev.slice(-500), event]);
  };

  // Simulate SSE connection for terminal events
  useState(() => {
    if (typeof window !== "undefined") {
      const source = new EventSource(`/api/sse/${campaignId}`);
      source.onmessage = (e) => {
        try {
          const data = JSON.parse(e.data);
          addTerminalEvent(data);
        } catch {
          // ignore
        }
      };
      return () => source.close();
    }
  });

  return (
    <div className="flex flex-col min-h-[calc(100vh-4rem)]">
      {/* Campaign header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-border bg-bg-surface">
        <div>
          <h1 className="text-lg font-bold text-text-primary">
            {activeCampaign?.name || `Campaign ${campaignId}`}
          </h1>
          {activeCampaign && (
            <span
              className={`inline-block mt-1 px-2 py-0.5 rounded-full text-xs font-medium ${
                activeCampaign.status === "running"
                  ? "bg-amber-500/20 text-amber-400"
                  : activeCampaign.status === "complete"
                    ? "bg-green-500/20 text-green-400"
                    : "bg-gray-500/20 text-gray-400"
              }`}
            >
              {activeCampaign.status}
            </span>
          )}
        </div>
        <ResourceIndicator onClick={() => setShowResourcePanel(true)} />
      </div>

      {/* Tab navigation */}
      <nav className="flex gap-1 px-4 border-b border-border bg-bg-surface">
        {TABS.map((tab) => {
          const isActive = pathname === `/campaign/${campaignId}${tab.href}`;
          return (
            <Link
              key={tab.href}
              href={`/campaign/${campaignId}${tab.href}`}
              className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
                isActive
                  ? "border-accent-primary text-accent-primary"
                  : "border-transparent text-text-secondary hover:text-text-primary"
              }`}
            >
              {tab.label}
            </Link>
          );
        })}
      </nav>

      {/* Content */}
      <main className="flex-1 p-4">{children}</main>

      {/* Live Terminal */}
      <LiveTerminal events={terminalEvents} />

      {/* Resource Panel */}
      {showResourcePanel && (
        <ResourcePanel
          status={resourceStatus}
          onClose={() => setShowResourcePanel(false)}
        />
      )}
    </div>
  );
}
