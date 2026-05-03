"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { ResourceStatus } from "@/types/schema";

interface ResourceIndicatorProps {
  onClick: () => void;
}

const TIER_COLORS: Record<string, string> = {
  green: "bg-neon-green",
  yellow: "bg-warning",
  red: "bg-danger",
  critical: "bg-bg-void border border-danger",
};

export default function ResourceIndicator({ onClick }: ResourceIndicatorProps) {
  const [status, setStatus] = useState<ResourceStatus | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchStatus = async () => {
      try {
        const data = await api.getResourceStatus();
        setStatus(data);
      } catch {
        // ignore — endpoint may not exist yet
      } finally {
        setLoading(false);
      }
    };

    fetchStatus();
    const interval = setInterval(fetchStatus, 10000);
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return <div className="w-3 h-3 rounded-full bg-text-muted animate-pulse" />;
  }

  return (
    <button
      onClick={onClick}
      className="flex items-center gap-2"
      title={`Resource tier: ${status?.tier}`}
    >
      <div className={`w-3 h-3 rounded-full ${TIER_COLORS[status?.tier || "green"]}`} />
      <span className="text-xs text-text-secondary capitalize">{status?.tier}</span>
    </button>
  );
}
