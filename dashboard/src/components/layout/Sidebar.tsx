"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Target,
  LayoutDashboard,
  Network,
  Shield,
  Cloud,
  Activity,
  Bug,
  GitGraph,
  Settings,
} from "lucide-react";

const NAV_ITEMS = [
  { href: "/", label: "Dashboard", icon: LayoutDashboard },
  { href: "/campaign", label: "New Campaign", icon: Target },
  { href: "/campaign/c2", label: "C2 Console", icon: Network },
  { href: "/campaign/graph", label: "Attack Graph", icon: GitGraph },
  { href: "/campaign/assets", label: "Assets", icon: Activity },
  { href: "/campaign/cloud", label: "Cloud", icon: Cloud },
  { href: "/campaign/vulns", label: "Vulnerabilities", icon: Bug },
  { href: "/campaign/findings", label: "All Findings", icon: Shield },
] as const;

export default function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="fixed inset-y-0 left-0 z-30 flex w-56 flex-col border-r border-border bg-bg-secondary">
      {/* Logo */}
      <div className="flex h-14 items-center gap-2 border-b border-border px-4">
        <Shield className="h-6 w-6 text-accent" />
        <span className="text-sm font-bold tracking-wide text-text-primary">
          WebAppBH
        </span>
      </div>

      {/* Navigation */}
      <nav className="flex-1 space-y-1 px-2 py-3">
        {NAV_ITEMS.map(({ href, label, icon: Icon }) => {
          const active = pathname === href;
          return (
            <Link
              key={href}
              href={href}
              className={`flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors ${
                active
                  ? "bg-bg-surface text-accent"
                  : "text-text-secondary hover:bg-bg-tertiary hover:text-text-primary"
              }`}
            >
              <Icon className="h-4 w-4 shrink-0" />
              {label}
            </Link>
          );
        })}
      </nav>

      {/* Footer */}
      <div className="border-t border-border px-4 py-3">
        <Link
          href="/settings"
          className="flex items-center gap-2 text-xs text-text-muted hover:text-text-secondary"
        >
          <Settings className="h-3.5 w-3.5" />
          Settings
        </Link>
      </div>
    </aside>
  );
}
