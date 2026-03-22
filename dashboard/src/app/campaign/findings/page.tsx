"use client";

import Link from "next/link";
import { Cloud, Shield, Server } from "lucide-react";
import CorrelationView from "@/components/findings/CorrelationView";

const TABS = [
  { key: "assets", label: "Assets", icon: Server, href: "/campaign/assets" },
  { key: "cloud", label: "Cloud", icon: Cloud, href: "/campaign/cloud" },
  { key: "vulns", label: "Vulnerabilities", icon: Shield, href: "/campaign/vulns" },
] as const;

export default function FindingsPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-text-primary">All Findings</h1>
        <p className="mt-1 text-sm text-text-secondary">
          Browse all discovered data across every phase
        </p>
      </div>

      {/* Category cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        {TABS.map(({ key, label, icon: Icon, href }) => (
          <Link
            key={key}
            href={href}
            className="group flex items-center gap-4 rounded-lg border border-border bg-bg-secondary p-5 transition-colors hover:border-accent/50"
          >
            <Icon className="h-8 w-8 text-accent" />
            <div>
              <h3 className="text-sm font-medium text-text-primary group-hover:text-accent">
                {label}
              </h3>
              <p className="text-xs text-text-muted">
                View all {label.toLowerCase()}
              </p>
            </div>
          </Link>
        ))}
      </div>

      {/* Correlated findings */}
      <CorrelationView />
    </div>
  );
}
