"use client";

import { useState, useEffect, useRef, useMemo } from "react";
import { useRouter } from "next/navigation";
import {
  Search,
  LayoutDashboard,
  Target,
  Radio,
  Workflow,
  GitGraph,
  Activity,
  Cloud,
  Bug,
  Database,
  Pause,
  Download,
  RotateCcw,
} from "lucide-react";
import { useUIStore } from "@/stores/ui";
import { useCampaignStore } from "@/stores/campaign";
import { api } from "@/lib/api";

interface PaletteItem {
  id: string;
  label: string;
  category: "nav" | "action" | "asset";
  icon?: React.ElementType;
  action: () => void;
}

export default function CommandPalette() {
  const router = useRouter();
  const { commandPaletteOpen, setCommandPaletteOpen } = useUIStore();
  const activeTarget = useCampaignStore((s) => s.activeTarget);
  const [query, setQuery] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);

  // Keyboard shortcut to open
  useEffect(() => {
    function handleKey(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setCommandPaletteOpen(!commandPaletteOpen);
      }
      if (e.key === "Escape" && commandPaletteOpen) {
        setCommandPaletteOpen(false);
      }
    }
    document.addEventListener("keydown", handleKey);
    return () => document.removeEventListener("keydown", handleKey);
  }, [commandPaletteOpen, setCommandPaletteOpen]);

  // Focus input when opening
  useEffect(() => {
    if (commandPaletteOpen) {
      queueMicrotask(() => setQuery(""));
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [commandPaletteOpen]);

  const items: PaletteItem[] = useMemo(() => {
    const nav: PaletteItem[] = [
      { id: "nav-dash", label: "Go to Dashboard", category: "nav", icon: LayoutDashboard, action: () => router.push("/") },
      { id: "nav-new", label: "New Campaign", category: "nav", icon: Target, action: () => router.push("/campaign") },
      { id: "nav-c2", label: "C2 Console", category: "nav", icon: Radio, action: () => router.push("/campaign/c2") },
      { id: "nav-flow", label: "Phase Flow", category: "nav", icon: Workflow, action: () => router.push("/campaign/flow") },
      { id: "nav-graph", label: "Attack Graph", category: "nav", icon: GitGraph, action: () => router.push("/campaign/graph") },
      { id: "nav-assets", label: "Assets", category: "nav", icon: Activity, action: () => router.push("/campaign/assets") },
      { id: "nav-cloud", label: "Cloud Assets", category: "nav", icon: Cloud, action: () => router.push("/campaign/cloud") },
      { id: "nav-vulns", label: "Vulnerabilities", category: "nav", icon: Bug, action: () => router.push("/campaign/vulns") },
      { id: "nav-explorer", label: "Data Explorer", category: "nav", icon: Database, action: () => router.push("/campaign/explorer") },
    ];

    const actions: PaletteItem[] = [];
    if (activeTarget) {
      actions.push(
        {
          id: "act-pause", label: "Pause all workers", category: "action", icon: Pause,
          action: async () => {
            const jobs = useCampaignStore.getState().jobs;
            for (const j of jobs.filter((j) => j.status === "RUNNING")) {
              await api.controlWorker(j.container_name, "pause");
            }
          },
        },
        {
          id: "act-rescan", label: "Trigger rescan", category: "action", icon: RotateCcw,
          action: () => { api.triggerRescan(activeTarget.id); },
        },
        {
          id: "act-export", label: "Export findings (JSON)", category: "action", icon: Download,
          action: async () => {
            const [assets, vulns] = await Promise.all([
              api.getAssets(activeTarget.id),
              api.getVulnerabilities(activeTarget.id),
            ]);
            const blob = new Blob([JSON.stringify({ assets: assets.assets, vulnerabilities: vulns.vulnerabilities }, null, 2)], { type: "application/json" });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `${activeTarget.base_domain}-findings.json`;
            a.click();
            URL.revokeObjectURL(url);
          },
        },
      );
    }

    return [...nav, ...actions];
  }, [activeTarget, router]);

  const filtered = query.trim()
    ? items.filter((item) =>
        item.label.toLowerCase().includes(query.toLowerCase())
      )
    : items;

  const [selectedIdx, setSelectedIdx] = useState(0);

  useEffect(() => {
    queueMicrotask(() => setSelectedIdx(0));
  }, [query]);

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setSelectedIdx((i) => Math.min(i + 1, filtered.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setSelectedIdx((i) => Math.max(i - 1, 0));
    } else if (e.key === "Enter" && filtered[selectedIdx]) {
      e.preventDefault();
      filtered[selectedIdx].action();
      setCommandPaletteOpen(false);
    }
  }

  if (!commandPaletteOpen) return null;

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 z-50 bg-black/60 backdrop-blur-[2px]"
        onClick={() => setCommandPaletteOpen(false)}
      />

      {/* Palette */}
      <div data-testid="command-palette" className="fixed left-1/2 top-[20%] z-50 w-full max-w-md -translate-x-1/2 animate-fade-in">
        <div className="rounded-lg border border-border-accent bg-bg-secondary shadow-2xl overflow-hidden">
          {/* Search input */}
          <div className="flex items-center gap-2 border-b border-border px-3 py-2">
            <Search className="h-4 w-4 text-text-muted" />
            <input
              data-testid="command-input"
              ref={inputRef}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Search commands, pages, actions..."
              className="flex-1 bg-transparent text-sm text-text-primary placeholder:text-text-muted outline-none"
            />
            <kbd className="rounded border border-border px-1.5 py-0.5 text-[9px] text-text-muted">ESC</kbd>
          </div>

          {/* Results */}
          <div className="max-h-72 overflow-y-auto py-1">
            {filtered.length === 0 ? (
              <p className="px-3 py-4 text-center text-xs text-text-muted">
                No results
              </p>
            ) : (
              <>
                {["nav", "action"].map((cat) => {
                  const group = filtered.filter((f) => f.category === cat);
                  if (group.length === 0) return null;
                  return (
                    <div key={cat}>
                      <p className="section-label px-3 py-1">
                        {cat === "nav" ? "Navigation" : "Actions"}
                      </p>
                      {group.map((item) => {
                        const idx = filtered.indexOf(item);
                        const Icon = item.icon;
                        return (
                          <button
                            key={item.id}
                            data-testid="command-result"
                            onClick={() => {
                              item.action();
                              setCommandPaletteOpen(false);
                            }}
                            onMouseEnter={() => setSelectedIdx(idx)}
                            className={`flex w-full items-center gap-2.5 px-3 py-1.5 text-left text-xs transition-colors ${
                              idx === selectedIdx
                                ? "bg-bg-surface text-text-primary"
                                : "text-text-secondary hover:bg-bg-surface"
                            }`}
                          >
                            {Icon && <Icon className="h-3.5 w-3.5 shrink-0 text-text-muted" />}
                            <span>{item.label}</span>
                          </button>
                        );
                      })}
                    </div>
                  );
                })}
              </>
            )}
          </div>
        </div>
      </div>
    </>
  );
}
