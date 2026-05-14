"use client";

import { useEffect, useCallback } from "react";
import {
  X,
  Globe,
  Server,
  Network,
  Clock,
  Wrench,
  Shield,
  Link2,
  Hash,
} from "lucide-react";
import type { AssetWithLocations } from "@/lib/api";
import FingerprintPanel from "./FingerprintPanel";

interface AssetDetailDrawerProps {
  asset: AssetWithLocations | null;
  onClose: () => void;
}

const TYPE_ICONS: Record<string, React.ElementType> = {
  subdomain: Globe,
  ip: Server,
  url: Link2,
  cidr: Network,
};

export default function AssetDetailDrawer({
  asset,
  onClose,
}: AssetDetailDrawerProps) {
  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    },
    [onClose],
  );

  useEffect(() => {
    if (!asset) return;
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [asset, handleKeyDown]);

  if (!asset) return null;

  const Icon = TYPE_ICONS[asset.asset_type] ?? Globe;

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 z-40 bg-black/60"
        onClick={onClose}
      />

      {/* Drawer */}
      <div className="animate-slide-right fixed inset-y-0 right-0 z-50 w-[420px] border-l border-border bg-bg-secondary shadow-2xl">
        {/* Header */}
        <div className="flex h-14 items-center justify-between border-b border-border px-4">
          <div className="flex items-center gap-2 min-w-0">
            <Icon className="h-4 w-4 shrink-0 text-accent" />
            <span className="truncate font-mono text-sm text-text-primary">
              {asset.asset_value}
            </span>
          </div>
          <button
            onClick={onClose}
            className="rounded p-1 text-text-muted transition-colors hover:bg-bg-surface hover:text-text-primary"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Content */}
        <div className="h-[calc(100vh-3.5rem)] overflow-y-auto p-4 space-y-5">
          {/* Basic Info */}
          <section>
            <div className="section-label mb-2">ASSET DETAILS</div>
            <div className="space-y-2 rounded-lg border border-border bg-bg-tertiary p-3">
              <InfoRow label="Value" value={asset.asset_value} mono />
              <InfoRow label="Type" value={asset.asset_type} />
              <InfoRow
                label="Source Tool"
                value={asset.source_tool ?? "Unknown"}
                icon={Wrench}
              />
              <InfoRow
                label="Discovered"
                value={
                  asset.created_at
                    ? new Date(asset.created_at).toLocaleString()
                    : "Unknown"
                }
                icon={Clock}
                mono
              />
              <InfoRow
                label="Last Updated"
                value={
                  asset.updated_at
                    ? new Date(asset.updated_at).toLocaleString()
                    : "Unknown"
                }
                icon={Clock}
                mono
              />
            </div>
          </section>

          {/* Locations (Ports / Protocols / Services) */}
          {asset.locations.length > 0 && (
            <section>
              <div className="section-label mb-2">
                LOCATIONS ({asset.locations.length})
              </div>
              <div className="space-y-1.5">
                {asset.locations.map((loc) => (
                  <div
                    key={loc.id}
                    className="flex items-center justify-between rounded border border-border bg-bg-tertiary px-3 py-2"
                  >
                    <div className="flex items-center gap-2">
                      <Network className="h-3 w-3 text-neon-blue" />
                      <span className="font-mono text-xs text-text-primary">
                        {loc.port}
                      </span>
                      <span className="text-[10px] text-text-muted">/</span>
                      <span className="font-mono text-xs text-text-secondary">
                        {loc.protocol ?? "tcp"}
                      </span>
                    </div>
                    <div className="flex items-center gap-2">
                      {loc.service && (
                        <span className="rounded bg-neon-blue-glow px-1.5 py-0.5 font-mono text-[10px] text-neon-blue">
                          {loc.service}
                        </span>
                      )}
                      {loc.state && (
                        <span
                          className={`text-[10px] font-medium ${
                            loc.state === "open"
                              ? "text-neon-green"
                              : loc.state === "filtered"
                                ? "text-warning"
                                : "text-text-muted"
                          }`}
                        >
                          {loc.state}
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </section>
          )}

          {/* Fingerprint panel — rendered when a summary observation is present */}
          {(() => {
            const summaryObs = asset.observations?.find(
              (o) => o.tech_stack?.["_probe"] === "summary",
            );
            if (!summaryObs?.tech_stack) return null;
            return (
              <FingerprintPanel
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                obs={summaryObs.tech_stack as any}
              />
            );
          })()}

          {/* Placeholder sections for future data */}
          <section>
            <div className="section-label mb-2 flex items-center gap-1.5">
              <Shield className="h-3 w-3" />
              VULNERABILITIES
            </div>
            <div className="rounded-lg border border-border bg-bg-tertiary px-3 py-4 text-center text-xs text-text-muted">
              No vulnerabilities linked to this asset
            </div>
          </section>

          <section>
            <div className="section-label mb-2 flex items-center gap-1.5">
              <Hash className="h-3 w-3" />
              PARAMETERS
            </div>
            <div className="rounded-lg border border-border bg-bg-tertiary px-3 py-4 text-center text-xs text-text-muted">
              No parameters discovered yet
            </div>
          </section>
        </div>
      </div>
    </>
  );
}

function InfoRow({
  label,
  value,
  mono,
  icon: Icon,
}: {
  label: string;
  value: string;
  mono?: boolean;
  icon?: React.ElementType;
}) {
  return (
    <div className="flex items-start justify-between gap-2">
      <div className="flex items-center gap-1.5">
        {Icon && <Icon className="h-3 w-3 text-text-muted" />}
        <span className="text-[10px] uppercase tracking-wide text-text-muted">
          {label}
        </span>
      </div>
      <span
        className={`text-right text-xs text-text-primary ${mono ? "font-mono" : ""}`}
      >
        {value}
      </span>
    </div>
  );
}
