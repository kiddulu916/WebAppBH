// dashboard/src/components/assets/AssetNodeDrawer.tsx
"use client";

import { X, Shield, Clock, Wrench, Tag, Network } from "lucide-react";
import type { PathNodeDetail } from "@/lib/api";
import type { Location } from "@/types/schema";

const SCOPE_BADGE: Record<string, string> = {
  in_scope: "bg-neon-green-glow text-neon-green border-neon-green/20",
  out_of_scope: "bg-danger/10 text-danger border-danger/20",
  pending: "bg-sev-medium/10 text-sev-medium border-sev-medium/20",
  associated: "bg-neon-blue-glow text-neon-blue border-neon-blue/20",
  undetermined: "bg-bg-surface text-text-muted border-border",
};

const TYPE_BADGE: Record<string, string> = {
  directory: "bg-neon-orange/10 text-neon-orange border-neon-orange/20",
  file: "bg-bg-surface text-text-secondary border-border",
  sensitive_file: "bg-danger/10 text-danger border-danger/20",
  form: "bg-neon-blue-glow text-neon-blue border-neon-blue/20",
  url: "bg-bg-surface text-text-muted border-border",
};

const SEV_COLORS: Record<string, string> = {
  critical: "text-danger",
  high: "text-neon-orange",
  medium: "text-sev-medium",
  low: "text-neon-blue",
  info: "text-text-muted",
};

function Row({
  icon,
  label,
  value,
}: {
  icon: React.ReactNode;
  label: string;
  value: React.ReactNode;
}) {
  return (
    <div className="flex items-start gap-2 py-1.5 border-b border-border last:border-0">
      <span className="mt-0.5 text-text-muted flex-shrink-0">{icon}</span>
      <span className="text-xs text-text-muted w-20 flex-shrink-0">{label}</span>
      <span className="text-xs text-text-primary break-all">{value}</span>
    </div>
  );
}

export type DrawerState =
  | { type: "node"; detail: PathNodeDetail }
  | { type: "port"; location: Location };

export default function AssetNodeDrawer({
  state,
  onClose,
}: {
  state: DrawerState | null;
  onClose: () => void;
}) {
  if (!state) return null;

  return (
    <>
      {/* Backdrop */}
      <div className="fixed inset-0 z-40" onClick={onClose} />
      {/* Drawer */}
      <div className="fixed right-0 top-0 z-50 h-full w-80 border-l border-border bg-bg-secondary shadow-2xl overflow-y-auto">
        <div className="flex items-center justify-between border-b border-border px-4 py-3">
          <span className="text-sm font-semibold text-text-primary">
            {state.type === "node"
              ? state.detail.path_segment
              : `:${state.location.port}`}
          </span>
          <button
            onClick={onClose}
            className="rounded p-1 hover:bg-bg-tertiary transition-colors"
          >
            <X className="h-4 w-4 text-text-muted" />
          </button>
        </div>

        <div className="px-4 py-3">
          {state.type === "port" ? (
            <div className="space-y-1">
              <Row
                icon={<Network className="h-3.5 w-3.5" />}
                label="Port"
                value={
                  <span className="font-mono">{state.location.port}</span>
                }
              />
              <Row
                icon={<Network className="h-3.5 w-3.5" />}
                label="Protocol"
                value={state.location.protocol ?? "—"}
              />
              <Row
                icon={<Wrench className="h-3.5 w-3.5" />}
                label="Service"
                value={
                  <span className="font-mono">
                    {state.location.service ?? "—"}
                  </span>
                }
              />
              <Row
                icon={<Shield className="h-3.5 w-3.5" />}
                label="State"
                value={state.location.state ?? "—"}
              />
            </div>
          ) : (
            <div className="space-y-1">
              {state.detail.node_type && (
                <Row
                  icon={<Tag className="h-3.5 w-3.5" />}
                  label="Type"
                  value={
                    <span
                      className={`rounded border px-1.5 py-0.5 text-[10px] font-medium ${
                        TYPE_BADGE[state.detail.node_type] ?? TYPE_BADGE.url
                      }`}
                    >
                      {state.detail.node_type}
                    </span>
                  }
                />
              )}
              {state.detail.asset && (
                <>
                  <Row
                    icon={<Shield className="h-3.5 w-3.5" />}
                    label="Scope"
                    value={
                      <span
                        className={`rounded border px-1.5 py-0.5 text-[10px] font-medium ${
                          SCOPE_BADGE[state.detail.asset.scope_classification] ??
                          SCOPE_BADGE.undetermined
                        }`}
                      >
                        {state.detail.asset.scope_classification.replace(
                          /_/g,
                          " ",
                        )}
                      </span>
                    }
                  />
                  <Row
                    icon={<Wrench className="h-3.5 w-3.5" />}
                    label="Source"
                    value={
                      <span className="font-mono">
                        {state.detail.asset.source_tool ?? "—"}
                      </span>
                    }
                  />
                  <Row
                    icon={<Clock className="h-3.5 w-3.5" />}
                    label="Found"
                    value={
                      state.detail.asset.created_at
                        ? new Date(
                            state.detail.asset.created_at,
                          ).toLocaleString()
                        : "—"
                    }
                  />
                  {state.detail.asset.vuln_count > 0 && (
                    <Row
                      icon={<Shield className="h-3.5 w-3.5" />}
                      label="Vulns"
                      value={
                        <span className={`font-semibold ${SEV_COLORS.high}`}>
                          {state.detail.asset.vuln_count}
                        </span>
                      }
                    />
                  )}
                  {state.detail.asset.tech &&
                    Object.keys(state.detail.asset.tech).length > 0 && (
                      <div className="mt-3">
                        <p className="mb-1 text-[10px] font-medium uppercase tracking-wider text-text-muted">
                          Tech Stack
                        </p>
                        <pre className="rounded bg-bg-tertiary p-2 text-[10px] text-text-secondary overflow-x-auto">
                          {JSON.stringify(state.detail.asset.tech, null, 2)}
                        </pre>
                      </div>
                    )}
                </>
              )}
              <Row
                icon={<Wrench className="h-3.5 w-3.5" />}
                label="Path"
                value={
                  <span className="font-mono text-[10px]">
                    {state.detail.full_path}
                  </span>
                }
              />
            </div>
          )}
        </div>
      </div>
    </>
  );
}
