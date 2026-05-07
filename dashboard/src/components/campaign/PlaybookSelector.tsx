"use client";

import { useState } from "react";
import { Search, Globe, Code, Cloud, BookOpen, Plus } from "lucide-react";
import { api } from "@/lib/api";
import PlaybookEditor from "./PlaybookEditor";

const PLAYBOOKS = [
  {
    name: "wide_recon",
    label: "Wide Recon",
    description: "Full 7-stage reconnaissance pipeline for maximum asset discovery",
    icon: Search,
    accent: "neon-orange" as const,
  },
  {
    name: "deep_webapp",
    label: "Deep WebApp",
    description: "Focus on web application testing — skip port scanning and cloud enum",
    icon: Globe,
    accent: "neon-blue" as const,
  },
  {
    name: "api_focused",
    label: "API Focused",
    description: "Target API endpoints and parameters for API security testing",
    icon: Code,
    accent: "neon-green" as const,
  },
  {
    name: "cloud_first",
    label: "Cloud First",
    description: "Prioritize cloud asset discovery and cloud-specific vulnerabilities",
    icon: Cloud,
    accent: "neon-blue" as const,
  },
] as const;

interface PlaybookSelectorProps {
  value: string;
  onChange: (playbook: string) => void;
}

export default function PlaybookSelector({ value, onChange }: PlaybookSelectorProps) {
  const [showEditor, setShowEditor] = useState(false);

  const handleSaveCustom = async (playbook: {
    name: string;
    description: string;
    workers: import("@/lib/api").WorkerConfig[];
  }) => {
    try {
      await api.createPlaybook(playbook);
      onChange(playbook.name);
      setShowEditor(false);
    } catch {
      // toast shown by api.request()
    }
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <BookOpen className="h-4 w-4 text-neon-orange" />
        <span className="text-sm font-medium text-text-primary">Campaign Playbook</span>
      </div>
      <p className="text-xs text-text-muted">
        Select a strategy that determines phase priorities and tool weighting.
      </p>
      <div className="grid grid-cols-2 gap-2">
        {PLAYBOOKS.map((pb) => {
          const Icon = pb.icon;
          const selected = value === pb.name;
          return (
            <button
              key={pb.name}
              type="button"
              onClick={() => onChange(pb.name)}
              className={`rounded-lg border p-3 text-left transition-all ${
                selected
                  ? "border-neon-orange card-glow bg-neon-orange-glow"
                  : "border-border bg-bg-tertiary hover:border-border-accent"
              }`}
            >
              <div className="flex items-center gap-2">
                <Icon
                  className={`h-4 w-4 ${
                    selected ? "text-neon-orange" : "text-text-muted"
                  }`}
                />
                <span
                  className={`text-sm font-semibold ${
                    selected ? "text-neon-orange" : "text-text-primary"
                  }`}
                >
                  {pb.label}
                </span>
              </div>
              <p
                className={`mt-1.5 text-xs leading-relaxed ${
                  selected ? "text-text-secondary" : "text-text-muted"
                }`}
              >
                {pb.description}
              </p>
            </button>
          );
        })}
      </div>

      {/* Custom playbook option */}
      {!showEditor ? (
        <button
          type="button"
          onClick={() => setShowEditor(true)}
          className="flex w-full items-center justify-center gap-2 rounded-lg border border-dashed border-border-accent p-3 text-sm text-text-muted transition-colors hover:border-neon-orange hover:text-neon-orange"
        >
          <Plus className="h-4 w-4" />
          Create Custom Playbook
        </button>
      ) : (
        <PlaybookEditor
          onSave={handleSaveCustom}
          onCancel={() => setShowEditor(false)}
        />
      )}
    </div>
  );
}
