"use client";

import { useState, useCallback, useMemo } from "react";
import {
  ChevronDown,
  ChevronRight,
  Save,
  Layers,
  Check,
} from "lucide-react";

/* ------------------------------------------------------------------ */
/* Hardcoded phase/tool structure                                     */
/* ------------------------------------------------------------------ */

export interface PhaseConfig {
  id: string;
  label: string;
  tools: string[];
}

const DEFAULT_PHASES: PhaseConfig[] = [
  {
    id: "info_gathering",
    label: "WSTG 4.1 — Information Gathering",
    tools: [
      "search_engine_recon", "web_server_fingerprint", "web_server_metafiles",
      "enumerate_applications", "review_comments", "identify_entry_points",
      "map_execution_paths", "fingerprint_framework", "map_architecture",
      "map_application",
    ],
  },
  {
    id: "config_mgmt",
    label: "WSTG 4.2 — Configuration & Deployment",
    tools: [
      "network_config", "platform_config", "file_extension_handling",
      "backup_files", "api_discovery", "http_methods", "hsts_testing",
      "rpc_testing", "file_inclusion", "subdomain_takeover", "cloud_storage",
    ],
  },
  {
    id: "identity_mgmt",
    label: "WSTG 4.3 — Identity Management",
    tools: [
      "role_definitions", "registration_process", "account_provisioning",
      "account_enumeration", "weak_username_policy",
    ],
  },
  {
    id: "authentication",
    label: "WSTG 4.4 — Authentication",
    tools: [
      "credentials_transport", "default_credentials", "lockout_mechanism",
      "auth_bypass", "remember_password", "browser_cache",
      "weak_password_policy", "security_questions", "password_change",
      "multi_channel_auth",
    ],
  },
  {
    id: "authorization",
    label: "WSTG 4.5 — Authorization",
    tools: [
      "directory_traversal", "authz_bypass", "privilege_escalation", "idor",
    ],
  },
  {
    id: "session_mgmt",
    label: "WSTG 4.6 — Session Management",
    tools: [
      "session_scheme", "cookie_attributes", "session_fixation",
      "exposed_variables", "csrf", "logout_functionality",
      "session_timeout", "session_puzzling", "session_hijacking",
    ],
  },
  {
    id: "input_validation",
    label: "WSTG 4.7 — Input Validation",
    tools: [
      "reflected_xss", "stored_xss", "http_verb_tampering",
      "http_param_pollution", "sql_injection", "ldap_injection",
      "xml_injection", "ssti", "xpath_injection", "imap_smtp_injection",
      "code_injection", "command_injection", "format_string",
      "host_header_injection", "ssrf", "file_inclusion",
      "buffer_overflow", "http_smuggling", "websocket_injection",
    ],
  },
  {
    id: "error_handling",
    label: "WSTG 4.8 — Error Handling",
    tools: ["error_codes", "stack_traces"],
  },
  {
    id: "cryptography",
    label: "WSTG 4.9 — Cryptography",
    tools: ["tls_testing", "padding_oracle", "plaintext_transmission", "weak_crypto"],
  },
  {
    id: "business_logic",
    label: "WSTG 4.10 — Business Logic",
    tools: [
      "data_validation", "request_forgery", "integrity_checks",
      "process_timing", "rate_limiting", "workflow_bypass",
      "application_misuse", "file_upload_validation", "malicious_file_upload",
    ],
  },
  {
    id: "client_side",
    label: "WSTG 4.11 — Client-Side Testing",
    tools: [
      "dom_xss", "clickjacking", "csrf_tokens", "csp_bypass",
      "html5_injection", "web_storage", "client_side_logic",
      "dom_based_injection", "client_side_resource_manipulation",
      "client_side_auth", "xss_client_side", "css_injection",
      "malicious_upload_client",
    ],
  },
];

/* ------------------------------------------------------------------ */
/* Types                                                              */
/* ------------------------------------------------------------------ */

export interface WorkflowState {
  /** phaseId -> set of enabled tool names */
  phases: Record<string, Set<string>>;
}

interface WorkflowBuilderProps {
  value: WorkflowState;
  onChange: (state: WorkflowState) => void;
}

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

function initWorkflowState(): WorkflowState {
  const phases: Record<string, Set<string>> = {};
  for (const p of DEFAULT_PHASES) {
    phases[p.id] = new Set(p.tools);
  }
  return { phases };
}

export { initWorkflowState, DEFAULT_PHASES };

/* ------------------------------------------------------------------ */
/* Component                                                          */
/* ------------------------------------------------------------------ */

export default function WorkflowBuilder({ value, onChange }: WorkflowBuilderProps) {
  const [expanded, setExpanded] = useState<Record<string, boolean>>(() => {
    const m: Record<string, boolean> = {};
    for (const p of DEFAULT_PHASES) m[p.id] = true;
    return m;
  });

  const [saveInputOpen, setSaveInputOpen] = useState(false);
  const [playbookName, setPlaybookName] = useState("");
  const [savedMsg, setSavedMsg] = useState("");

  /* ---- derived counts ---- */
  const { enabledPhases, totalPhases, activeTools, totalTools } = useMemo(() => {
    let ep = 0;
    let at = 0;
    let tt = 0;
    for (const p of DEFAULT_PHASES) {
      const set = value.phases[p.id];
      const count = set ? set.size : 0;
      tt += p.tools.length;
      at += count;
      if (count > 0) ep += 1;
    }
    return { enabledPhases: ep, totalPhases: DEFAULT_PHASES.length, activeTools: at, totalTools: tt };
  }, [value]);

  /* ---- toggle helpers ---- */
  const togglePhase = useCallback(
    (phaseId: string) => {
      const phase = DEFAULT_PHASES.find((p) => p.id === phaseId);
      if (!phase) return;
      const current = value.phases[phaseId];
      const allEnabled = current && current.size === phase.tools.length;
      const next = { ...value.phases };
      next[phaseId] = allEnabled ? new Set<string>() : new Set(phase.tools);
      onChange({ phases: next });
    },
    [value, onChange],
  );

  const toggleTool = useCallback(
    (phaseId: string, tool: string) => {
      const current = value.phases[phaseId] ?? new Set<string>();
      const next = new Set(current);
      if (next.has(tool)) {
        next.delete(tool);
      } else {
        next.add(tool);
      }
      onChange({ phases: { ...value.phases, [phaseId]: next } });
    },
    [value, onChange],
  );

  const toggleExpand = useCallback((phaseId: string) => {
    setExpanded((prev) => ({ ...prev, [phaseId]: !prev[phaseId] }));
  }, []);

  /* ---- save custom playbook to localStorage ---- */
  const handleSave = useCallback(() => {
    if (!playbookName.trim()) return;
    const serializable: Record<string, string[]> = {};
    for (const [k, v] of Object.entries(value.phases)) {
      serializable[k] = Array.from(v);
    }
    const stored = JSON.parse(localStorage.getItem("webbh-custom-playbooks") ?? "{}");
    stored[playbookName.trim()] = serializable;
    localStorage.setItem("webbh-custom-playbooks", JSON.stringify(stored));
    setSavedMsg(`Saved "${playbookName.trim()}"`);
    setPlaybookName("");
    setSaveInputOpen(false);
    setTimeout(() => setSavedMsg(""), 3000);
  }, [playbookName, value]);

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <Layers className="h-4 w-4 text-neon-blue" />
        <span className="text-sm font-medium text-text-primary">Workflow Builder</span>
      </div>

      <p className="text-xs text-text-muted">
        Enable or disable phases and individual tools. Unchecking a phase disables all its tools.
      </p>

      {/* Phase tree */}
      <div className="space-y-1">
        {DEFAULT_PHASES.map((phase) => {
          const enabledSet = value.phases[phase.id] ?? new Set<string>();
          const allChecked = enabledSet.size === phase.tools.length;
          const someChecked = enabledSet.size > 0 && !allChecked;
          const isExpanded = expanded[phase.id] ?? false;

          return (
            <div
              key={phase.id}
              className="rounded-md border border-border bg-bg-tertiary overflow-hidden"
            >
              {/* Phase header */}
              <div className="flex items-center gap-2 px-3 py-2">
                <button
                  type="button"
                  onClick={() => toggleExpand(phase.id)}
                  className="text-text-muted hover:text-text-secondary transition-colors"
                >
                  {isExpanded ? (
                    <ChevronDown className="h-3.5 w-3.5" />
                  ) : (
                    <ChevronRight className="h-3.5 w-3.5" />
                  )}
                </button>

                {/* Phase checkbox */}
                <button
                  type="button"
                  onClick={() => togglePhase(phase.id)}
                  className={`flex h-4 w-4 shrink-0 items-center justify-center rounded border transition-colors ${
                    allChecked
                      ? "border-neon-orange bg-neon-orange"
                      : someChecked
                        ? "border-neon-orange bg-neon-orange/30"
                        : "border-border-accent bg-bg-surface"
                  }`}
                >
                  {(allChecked || someChecked) && (
                    <Check className="h-2.5 w-2.5 text-bg-primary" />
                  )}
                </button>

                <button
                  type="button"
                  onClick={() => toggleExpand(phase.id)}
                  className="flex-1 text-left"
                >
                  <span className="text-xs font-semibold text-text-primary">
                    {phase.label}
                  </span>
                  <span className="ml-2 text-[10px] text-text-muted">
                    {enabledSet.size}/{phase.tools.length} tools
                  </span>
                </button>
              </div>

              {/* Tools list */}
              {isExpanded && (
                <div className="border-t border-border bg-bg-secondary px-3 py-2 space-y-1 animate-fade-in">
                  {phase.tools.map((tool) => {
                    const checked = enabledSet.has(tool);
                    return (
                      <label
                        key={tool}
                        className="flex items-center gap-2.5 cursor-pointer py-0.5 group"
                      >
                        <button
                          type="button"
                          onClick={() => toggleTool(phase.id, tool)}
                          className={`flex h-3.5 w-3.5 shrink-0 items-center justify-center rounded-sm border transition-colors ${
                            checked
                              ? "border-neon-green bg-neon-green"
                              : "border-border-accent bg-bg-surface group-hover:border-text-muted"
                          }`}
                        >
                          {checked && (
                            <Check className="h-2 w-2 text-bg-primary" />
                          )}
                        </button>
                        <span
                          className={`font-mono text-xs transition-colors ${
                            checked ? "text-text-primary" : "text-text-muted"
                          }`}
                        >
                          {tool}
                        </span>
                      </label>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Summary */}
      <div className="flex items-center justify-between rounded-md border border-border bg-bg-surface px-3 py-2">
        <span className="text-xs text-text-secondary">
          <span className="font-mono text-neon-green">{enabledPhases}</span> of{" "}
          <span className="font-mono">{totalPhases}</span> phases enabled,{" "}
          <span className="font-mono text-neon-blue">{activeTools}</span> of{" "}
          <span className="font-mono">{totalTools}</span> tools active
        </span>
      </div>

      {/* Save as custom playbook */}
      <div className="space-y-2">
        {!saveInputOpen ? (
          <button
            type="button"
            onClick={() => setSaveInputOpen(true)}
            className="flex items-center gap-1.5 text-xs text-text-muted hover:text-neon-orange transition-colors"
          >
            <Save className="h-3 w-3" />
            Save as custom playbook
          </button>
        ) : (
          <div className="flex items-center gap-2 animate-fade-in">
            <input
              type="text"
              value={playbookName}
              onChange={(e) => setPlaybookName(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleSave()}
              placeholder="Playbook name..."
              className="flex-1 rounded-md border border-border bg-bg-tertiary px-2.5 py-1.5 font-mono text-xs text-text-primary placeholder:text-text-muted input-focus"
              autoFocus
            />
            <button
              type="button"
              onClick={handleSave}
              disabled={!playbookName.trim()}
              className="rounded-md bg-neon-orange/15 px-3 py-1.5 text-xs font-medium text-neon-orange transition-colors hover:bg-neon-orange/25 disabled:opacity-40"
            >
              Save
            </button>
            <button
              type="button"
              onClick={() => {
                setSaveInputOpen(false);
                setPlaybookName("");
              }}
              className="text-xs text-text-muted hover:text-text-secondary transition-colors"
            >
              Cancel
            </button>
          </div>
        )}

        {savedMsg && (
          <p className="text-[10px] text-neon-green animate-fade-in">{savedMsg}</p>
        )}
      </div>
    </div>
  );
}
