"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Shield,
  LayoutDashboard,
  Target,
  Crosshair,
  Radio,
  GitGraph,
  Activity,
  Cloud,
  Bug,
  Search,
  Workflow,
  CalendarClock,
  DollarSign,
  Brain,
  Settings,
} from "lucide-react";
import { useUIStore } from "@/stores/ui";

const NAV_ITEMS = [
  { href: "/", label: "Dashboard", icon: LayoutDashboard },
  { href: "/campaign", label: "New Campaign", icon: Target },
  { href: "/campaign/targets", label: "Targets", icon: Crosshair },
  { href: "/campaign/c2", label: "C2 Console", icon: Radio },
  { href: "/campaign/flow", label: "Phase Flow", icon: Workflow },
  { href: "/campaign/graph", label: "Attack Graph", icon: GitGraph },
  { href: "/campaign/assets", label: "Assets", icon: Activity },
  { href: "/campaign/cloud", label: "Cloud", icon: Cloud },
  { href: "/campaign/vulns", label: "Vulnerabilities", icon: Bug },
  { href: "/campaign/triage", label: "AI Triage", icon: Brain },
  { href: "/campaign/findings", label: "Findings", icon: Search },
  { href: "/campaign/bounties", label: "Bounties", icon: DollarSign },
  { href: "/campaign/schedules", label: "Schedules", icon: CalendarClock },
] as const;

export default function IconRail() {
  const pathname = usePathname();
  const { sidebarExpanded, setSidebarExpanded } = useUIStore();

  return (
    <aside
      onMouseEnter={() => setSidebarExpanded(true)}
      onMouseLeave={() => setSidebarExpanded(false)}
      className={`fixed inset-y-0 left-0 z-40 flex flex-col border-r border-border bg-bg-secondary transition-all duration-200 ${
        sidebarExpanded ? "w-48" : "w-12"
      }`}
    >
      {/* Logo */}
      <div className="flex h-11 items-center gap-2 border-b border-border px-3">
        <Shield className="h-5 w-5 shrink-0 text-neon-orange" />
        {sidebarExpanded && (
          <span className="whitespace-nowrap text-xs font-bold tracking-wider text-text-primary">
            WebAppBH
          </span>
        )}
      </div>

      {/* Nav */}
      <nav className="flex-1 space-y-0.5 px-1.5 py-2 overflow-y-auto overflow-x-hidden">
        {NAV_ITEMS.map(({ href, label, icon: Icon }) => {
          const active = pathname === href;
          return (
            <Link
              key={href}
              href={href}
              title={!sidebarExpanded ? label : undefined}
              className={`flex items-center gap-2.5 rounded-md px-2 py-1.5 text-xs transition-colors ${
                active
                  ? "bg-neon-orange-glow text-neon-orange"
                  : "text-text-muted hover:bg-bg-surface hover:text-text-secondary"
              }`}
            >
              <Icon className="h-4 w-4 shrink-0" />
              {sidebarExpanded && (
                <span className="truncate">{label}</span>
              )}
            </Link>
          );
        })}
      </nav>

      {/* Footer */}
      <div className="border-t border-border px-1.5 py-2">
        <Link
          href="/settings"
          title={!sidebarExpanded ? "Settings" : undefined}
          className="flex items-center gap-2.5 rounded-md px-2 py-1.5 text-xs text-text-muted hover:bg-bg-surface hover:text-text-secondary transition-colors"
        >
          <Settings className="h-4 w-4 shrink-0" />
          {sidebarExpanded && <span>Settings</span>}
        </Link>
      </div>
    </aside>
  );
}
