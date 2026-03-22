"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  Globe,
  Bug,
  Cpu,
  Cloud,
  Terminal,
  GitBranch,
  Network,
  Database,
  Rocket,
  Clock,
} from "lucide-react";
import { useCampaignStore } from "@/stores/campaign";
import { api } from "@/lib/api";
import CampaignPicker from "@/components/campaign/CampaignPicker";

export default function DashboardHome() {
  const activeTarget = useCampaignStore((s) => s.activeTarget);
  const counters = useCampaignStore((s) => s.counters);
  const [cloudCount, setCloudCount] = useState(0);

  useEffect(() => {
    if (!activeTarget) return;
    api
      .getCloudAssets(activeTarget.id)
      .then((res) => setCloudCount(res.cloud_assets.length))
      .catch(() => {});
  }, [activeTarget]);

  /* No active campaign — show launch CTA */
  if (!activeTarget) {
    return (
      <div className="flex min-h-[70vh] items-center justify-center">
        <div className="w-full max-w-md rounded-lg border border-border bg-bg-secondary p-10 text-center animate-fade-in">
          <Rocket className="mx-auto h-10 w-10 text-neon-orange" />
          <h1 className="mt-5 text-2xl font-bold text-text-primary">
            WebAppBH
          </h1>
          <p className="mt-2 text-sm text-text-secondary">
            Bug Bounty Framework — Command &amp; Control
          </p>
          <Link
            href="/campaign"
            className="btn-launch mt-6 inline-block rounded-md px-6 py-2.5 text-sm"
          >
            Launch a Campaign
          </Link>
          <div className="mt-8 border-t border-border pt-6">
            <p className="section-label mb-4">Or select existing</p>
            <CampaignPicker />
          </div>
        </div>
      </div>
    );
  }

  /* Active campaign — full dashboard */
  const timeSince = activeTarget.created_at
    ? formatTimeSince(activeTarget.created_at)
    : "—";

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div>
        <h1 className="flex items-center gap-3 text-2xl font-bold text-text-primary">
          <Globe className="h-5 w-5 text-neon-orange" />
          <span className="font-mono text-neon-orange">
            {activeTarget.base_domain}
          </span>
        </h1>
        <p className="mt-1 text-sm text-text-secondary">
          {activeTarget.company_name}
        </p>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard
          label="Assets"
          value={counters.assets}
          icon={<Globe className="h-5 w-5 text-neon-blue" />}
          glowClass="glow-blue"
        />
        <StatCard
          label="Vulnerabilities"
          value={counters.vulns}
          icon={<Bug className="h-5 w-5 text-neon-orange" />}
          glowClass="glow-orange"
        />
        <StatCard
          label="Workers"
          value={counters.workers}
          icon={<Cpu className="h-5 w-5 text-neon-green" />}
          glowClass="glow-green"
        />
        <StatCard
          label="Cloud Assets"
          value={cloudCount}
          icon={<Cloud className="h-5 w-5 text-neon-blue" />}
          glowClass="glow-blue"
        />
      </div>

      {/* Quick links */}
      <div>
        <p className="section-label mb-3">Quick Links</p>
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          <QuickLink
            href="/campaign/c2"
            icon={<Terminal className="h-5 w-5 text-neon-green" />}
            title="C2 Console"
            desc="Monitor and control workers"
          />
          <QuickLink
            href="/campaign/c2"
            icon={<GitBranch className="h-5 w-5 text-neon-blue" />}
            title="Phase Flow"
            desc="Track pipeline stage progress"
          />
          <QuickLink
            href="/campaign/graph"
            icon={<Network className="h-5 w-5 text-neon-orange" />}
            title="Attack Graph"
            desc="Visualize attack surface"
          />
          <QuickLink
            href="/campaign/findings"
            icon={<Database className="h-5 w-5 text-neon-blue" />}
            title="Data Explorer"
            desc="Browse all collected data"
          />
        </div>
      </div>

      {/* Active campaign info */}
      <div className="rounded-lg border border-border bg-bg-secondary p-5">
        <p className="section-label mb-3">Active Campaign</p>
        <dl className="grid grid-cols-2 gap-4 text-sm lg:grid-cols-4">
          <div>
            <dt className="text-text-muted">Company</dt>
            <dd className="mt-0.5 text-text-primary">
              {activeTarget.company_name}
            </dd>
          </div>
          <div>
            <dt className="text-text-muted">Domain</dt>
            <dd className="mt-0.5 font-mono text-neon-orange">
              {activeTarget.base_domain}
            </dd>
          </div>
          <div>
            <dt className="text-text-muted">Queue Depth</dt>
            <dd className="mt-0.5 font-mono text-text-primary">
              {counters.queueDepth}
            </dd>
          </div>
          <div>
            <dt className="flex items-center gap-1 text-text-muted">
              <Clock className="h-3 w-3" />
              Uptime
            </dt>
            <dd className="mt-0.5 font-mono text-text-primary">{timeSince}</dd>
          </div>
        </dl>
      </div>
    </div>
  );
}

/* ── Stat Card ── */

function StatCard({
  label,
  value,
  icon,
  glowClass,
}: {
  label: string;
  value: number;
  icon: React.ReactNode;
  glowClass: string;
}) {
  return (
    <div
      className={`group rounded-lg border border-border bg-bg-secondary p-4 transition-all hover:${glowClass} hover:border-border-accent`}
    >
      <div className="flex items-center justify-between">
        {icon}
        <span className="font-mono text-2xl font-bold text-text-primary">
          {value}
        </span>
      </div>
      <p className="mt-2 text-xs text-text-muted">{label}</p>
    </div>
  );
}

/* ── Quick Link Card ── */

function QuickLink({
  href,
  icon,
  title,
  desc,
}: {
  href: string;
  icon: React.ReactNode;
  title: string;
  desc: string;
}) {
  return (
    <Link
      href={href}
      className="group rounded-lg border border-border bg-bg-secondary p-4 transition-all hover:border-neon-orange/40 hover:glow-orange"
    >
      <div className="mb-2">{icon}</div>
      <h3 className="text-sm font-medium text-text-primary group-hover:text-neon-orange">
        {title}
      </h3>
      <p className="mt-0.5 text-xs text-text-muted">{desc}</p>
    </Link>
  );
}

/* ── Helpers ── */

function formatTimeSince(iso: string): string {
  const ms = Date.now() - new Date(iso).getTime();
  const hours = Math.floor(ms / 3_600_000);
  const days = Math.floor(hours / 24);
  if (days > 0) return `${days}d ${hours % 24}h`;
  const mins = Math.floor(ms / 60_000);
  if (hours > 0) return `${hours}h ${mins % 60}m`;
  return `${mins}m`;
}
