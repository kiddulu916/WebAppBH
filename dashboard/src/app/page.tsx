"use client";

import Link from "next/link";
import { Target, Activity, Shield, Cloud } from "lucide-react";
import { useCampaignStore } from "@/stores/campaign";

export default function DashboardHome() {
  const { activeTarget } = useCampaignStore();

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-bold text-text-primary">Dashboard</h1>
        <p className="mt-1 text-sm text-text-secondary">
          WebAppBH Bug Bounty Framework — Command & Control
        </p>
      </div>

      {/* Quick Actions */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Link
          href="/campaign"
          className="group rounded-lg border border-border bg-bg-secondary p-5 transition-colors hover:border-accent/50"
        >
          <Target className="mb-3 h-6 w-6 text-accent" />
          <h3 className="text-sm font-medium text-text-primary group-hover:text-accent">
            New Campaign
          </h3>
          <p className="mt-1 text-xs text-text-muted">
            Initialize a new target scan
          </p>
        </Link>

        <Link
          href="/campaign/c2"
          className="group rounded-lg border border-border bg-bg-secondary p-5 transition-colors hover:border-accent/50"
        >
          <Activity className="mb-3 h-6 w-6 text-success" />
          <h3 className="text-sm font-medium text-text-primary group-hover:text-accent">
            C2 Console
          </h3>
          <p className="mt-1 text-xs text-text-muted">
            Monitor and control workers
          </p>
        </Link>

        <Link
          href="/campaign/vulns"
          className="group rounded-lg border border-border bg-bg-secondary p-5 transition-colors hover:border-accent/50"
        >
          <Shield className="mb-3 h-6 w-6 text-danger" />
          <h3 className="text-sm font-medium text-text-primary group-hover:text-accent">
            Vulnerabilities
          </h3>
          <p className="mt-1 text-xs text-text-muted">
            Review discovered findings
          </p>
        </Link>

        <Link
          href="/campaign/cloud"
          className="group rounded-lg border border-border bg-bg-secondary p-5 transition-colors hover:border-accent/50"
        >
          <Cloud className="mb-3 h-6 w-6 text-warning" />
          <h3 className="text-sm font-medium text-text-primary group-hover:text-accent">
            Cloud Assets
          </h3>
          <p className="mt-1 text-xs text-text-muted">
            AWS / Azure / GCP findings
          </p>
        </Link>
      </div>

      {/* Active Campaign Summary */}
      {activeTarget && (
        <div className="rounded-lg border border-border bg-bg-secondary p-6">
          <h2 className="mb-3 text-lg font-semibold text-text-primary">
            Active Campaign
          </h2>
          <dl className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <dt className="text-text-muted">Company</dt>
              <dd className="mt-0.5 text-text-primary">{activeTarget.company_name}</dd>
            </div>
            <div>
              <dt className="text-text-muted">Domain</dt>
              <dd className="mt-0.5 text-text-primary">{activeTarget.base_domain}</dd>
            </div>
          </dl>
        </div>
      )}
    </div>
  );
}
