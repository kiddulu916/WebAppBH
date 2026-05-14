"use client";

import { Cpu, Shield, Globe, Server, Code } from "lucide-react";

type SlotResult =
  | { vendor: string; confidence: number; signals: unknown[]; conflict: false }
  | { vendor: string; confidence: number; candidates: unknown[]; conflict: true }
  | { vendor: null; confidence: number; signals: unknown[]; conflict: false };

type TlsSummary = {
  tls_version?: string;
  cert_issuer?: string;
  alpn?: string[];
  ja3s?: string;
};

interface Fingerprint {
  edge: SlotResult;
  origin_server: SlotResult;
  framework: SlotResult;
  waf: SlotResult;
  os?: SlotResult;
  tls?: TlsSummary;
}

interface FingerprintObs {
  _probe: "summary";
  intensity: string;
  partial: boolean;
  fingerprint: Fingerprint;
  raw_probe_obs_ids?: number[];
}

interface FingerprintPanelProps {
  obs: FingerprintObs;
}

function confidenceBar(confidence: number) {
  const pct = Math.round(Math.min(confidence, 1) * 100);
  return (
    <div className="flex items-center gap-1.5">
      <div className="h-1.5 w-16 rounded-full bg-border overflow-hidden">
        <div
          className="h-full rounded-full bg-neon-green transition-all"
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="text-[9px] text-text-muted font-mono">{pct}%</span>
    </div>
  );
}

function SlotRow({
  label,
  slot,
  icon: Icon,
}: {
  label: string;
  slot: SlotResult | undefined;
  icon: React.ElementType;
}) {
  if (!slot) return null;
  const vendor = slot.vendor ?? "—";
  return (
    <div
      className="flex items-start justify-between gap-2 py-1 border-b border-border last:border-0"
      data-testid={`slot-${label.toLowerCase()}`}
    >
      <div className="flex items-center gap-1.5">
        <Icon className="h-3 w-3 text-text-muted shrink-0" />
        <span className="text-[10px] uppercase tracking-wide text-text-muted w-20 shrink-0">
          {label}
        </span>
      </div>
      <div className="flex flex-col items-end gap-0.5">
        <span className="font-mono text-xs text-text-primary">
          {slot.conflict ? (
            <span className="text-warning">{vendor} (conflict)</span>
          ) : (
            vendor
          )}
        </span>
        {slot.vendor && confidenceBar(slot.confidence)}
      </div>
    </div>
  );
}

export default function FingerprintPanel({ obs }: FingerprintPanelProps) {
  const { fingerprint, intensity, partial } = obs;

  return (
    <section data-testid="fingerprint-panel">
      <div className="section-label mb-2 flex items-center gap-1.5">
        <Cpu className="h-3 w-3" />
        FINGERPRINT
        {partial && (
          <span className="ml-1 rounded bg-warning/20 px-1 py-0.5 text-[9px] text-warning">
            partial
          </span>
        )}
        <span className="ml-auto rounded bg-bg-tertiary px-1.5 py-0.5 font-mono text-[9px] text-text-muted capitalize">
          {intensity}
        </span>
      </div>

      <div className="rounded-lg border border-border bg-bg-tertiary p-3 space-y-0">
        <SlotRow label="Edge" slot={fingerprint.edge} icon={Globe} />
        <SlotRow label="Origin" slot={fingerprint.origin_server} icon={Server} />
        <SlotRow label="Framework" slot={fingerprint.framework} icon={Code} />
        <SlotRow label="WAF" slot={fingerprint.waf} icon={Shield} />

        {fingerprint.tls && fingerprint.tls.tls_version && (
          <div className="flex items-start justify-between gap-2 py-1">
            <div className="flex items-center gap-1.5">
              <Shield className="h-3 w-3 text-neon-blue shrink-0" />
              <span className="text-[10px] uppercase tracking-wide text-text-muted w-20 shrink-0">
                TLS
              </span>
            </div>
            <span className="font-mono text-xs text-neon-blue">
              {fingerprint.tls.tls_version}
            </span>
          </div>
        )}
      </div>
    </section>
  );
}
