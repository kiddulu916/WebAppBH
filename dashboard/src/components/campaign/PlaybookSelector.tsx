"use client";

import { useState } from "react";
import { BookOpen, Search, Globe, Cloud, Code } from "lucide-react";

const PLAYBOOKS = [
  {
    name: "wide_recon",
    label: "Wide Recon",
    description: "Full 7-stage reconnaissance pipeline for maximum asset discovery",
    icon: Search,
  },
  {
    name: "deep_webapp",
    label: "Deep WebApp",
    description: "Focus on web application testing — skip port scanning and cloud enum",
    icon: Globe,
  },
  {
    name: "api_focused",
    label: "API Focused",
    description: "Target API endpoints and parameters for API security testing",
    icon: Code,
  },
  {
    name: "cloud_first",
    label: "Cloud First",
    description: "Prioritize cloud asset discovery and cloud-specific vulnerabilities",
    icon: Cloud,
  },
] as const;

interface PlaybookSelectorProps {
  value: string;
  onChange: (playbook: string) => void;
}

export default function PlaybookSelector({ value, onChange }: PlaybookSelectorProps) {
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <BookOpen className="h-4 w-4 text-accent" />
        <span className="text-sm font-medium text-text-primary">Campaign Playbook</span>
      </div>
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
        {PLAYBOOKS.map((pb) => {
          const Icon = pb.icon;
          const selected = value === pb.name;
          return (
            <button
              key={pb.name}
              type="button"
              onClick={() => onChange(pb.name)}
              className={`rounded-lg border p-3 text-left transition-colors ${
                selected
                  ? "border-accent bg-accent/10"
                  : "border-border bg-bg-secondary hover:border-accent/50"
              }`}
            >
              <div className="flex items-center gap-2">
                <Icon className={`h-4 w-4 ${selected ? "text-accent" : "text-text-muted"}`} />
                <span className={`text-sm font-medium ${selected ? "text-accent" : "text-text-primary"}`}>
                  {pb.label}
                </span>
              </div>
              <p className="mt-1 text-xs text-text-muted">{pb.description}</p>
            </button>
          );
        })}
      </div>
    </div>
  );
}
