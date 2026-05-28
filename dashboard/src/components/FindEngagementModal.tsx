"use client";

import { useState, useRef } from "react";
import { toast } from "sonner";
import {
  searchEngagement,
  fetchEngagement,
  type ProgramCandidate,
  type CampaignFormPrefill,
  type StageRule,
} from "@/lib/api";

const PLATFORMS = ["hackerone", "bugcrowd", "intigriti", "yeswehack"] as const;
type Platform = (typeof PLATFORMS)[number];

const ALL_STAGES = [
  "search_engine_recon","web_server_fingerprint","web_server_metafiles","enumerate_applications",
  "review_comments","identify_entry_points","aggregate_entry_points","map_execution_paths",
  "review_comments_deep","fingerprint_framework","map_architecture","map_application",
  "network_config","network_config_cred_test","platform_config","file_extension_handling",
  "backup_files","admin_interface_enumeration","api_discovery","http_methods","hsts_testing",
  "rpc_testing","file_permission","file_inclusion","subdomain_takeover","cloud_storage",
  "csp_testing","path_confusion","security_headers","role_definitions","registration_process",
  "account_provisioning","account_enumeration","weak_username_policy","credentials_transport",
  "default_credentials","lockout_mechanism","auth_bypass","remember_password","browser_cache",
  "weak_password_policy","security_questions","password_change","multi_channel_auth",
  "directory_traversal","authz_bypass","privilege_escalation","idor","session_scheme",
  "cookie_attributes","session_fixation","exposed_variables","csrf","logout_functionality",
  "session_timeout","session_puzzling","session_hijacking","reflected_xss","stored_xss",
  "http_verb_tampering","http_param_pollution","sql_injection","ldap_injection","xml_injection",
  "ssti","xpath_injection","imap_smtp_injection","code_injection","command_injection",
  "format_string","host_header_injection","ssrf","buffer_overflow","http_smuggling",
  "websocket_injection","error_codes","stack_traces","tls_testing","padding_oracle",
  "plaintext_transmission","weak_crypto","data_validation","request_forgery","integrity_checks",
  "process_timing","rate_limiting","workflow_bypass","application_misuse","file_upload_validation",
  "malicious_file_upload","dom_xss","clickjacking","csrf_tokens","csp_bypass","html5_injection",
  "web_storage","client_side_logic","dom_based_injection","client_side_resource_manipulation",
  "client_side_auth","xss_client_side","css_injection","malicious_upload_client",
];

interface Props {
  onApply: (prefill: CampaignFormPrefill) => void;
  onClose: () => void;
}

export default function FindEngagementModal({ onApply, onClose }: Props) {
  const [step, setStep] = useState<1 | 2 | 3 | 4>(1);
  const [loading, setLoading] = useState(false);

  const [platform, setPlatform] = useState<Platform>("hackerone");
  const [companyName, setCompanyName] = useState("");
  const [apiToken, setApiToken] = useState("");

  const [candidates, setCandidates] = useState<ProgramCandidate[]>([]);

  const [prefill, setPrefill] = useState<CampaignFormPrefill | null>(null);
  const [editSeeds, setEditSeeds] = useState<string[]>([]);
  const [editInScope, setEditInScope] = useState<string[]>([]);
  const [editOutOfScope, setEditOutOfScope] = useState<string[]>([]);
  const [editRateLimit, setEditRateLimit] = useState(50);
  const [editHeaders, setEditHeaders] = useState<{ key: string; value: string }[]>([]);
  const [editStageRules, setEditStageRules] = useState<Record<string, StageRule>>({});
  const [guidelinesOpen, setGuidelinesOpen] = useState(false);
  const [addStage, setAddStage] = useState("");
  const selectedCandidate = useRef<ProgramCandidate | null>(null);

  function loadPrefill(p: CampaignFormPrefill) {
    setPrefill(p);
    setEditSeeds(p.seed_targets);
    setEditInScope(p.in_scope);
    setEditOutOfScope(p.out_of_scope);
    setEditRateLimit(p.rate_limit ?? 50);
    setEditHeaders(
      Object.entries(p.custom_headers).map(([key, value]) => ({ key, value }))
    );
    setEditStageRules({ ...p.conditional_stages });
    setStep(3);
  }

  async function handleSearch() {
    if (!companyName.trim()) { toast.error("Enter a company name"); return; }
    setLoading(true);
    try {
      const creds = platform === "hackerone" ? { token: apiToken } : undefined;
      const resp = await searchEngagement({ platform, company_name: companyName, credentials: creds });
      if (resp.type === "prefill") {
        loadPrefill(resp.data);
      } else {
        setCandidates(resp.data);
        setStep(2);
      }
    } catch {
      // toast already shown by api.ts request()
    } finally {
      setLoading(false);
    }
  }

  async function handlePickCandidate(c: ProgramCandidate) {
    selectedCandidate.current = c;
    setLoading(true);
    try {
      const creds = platform === "hackerone" ? { token: apiToken } : undefined;
      const p = await fetchEngagement({ platform, handle: c.handle, url: c.url, credentials: creds, use_llm: false });
      loadPrefill(p);
    } catch {
      // toast already shown
    } finally {
      setLoading(false);
    }
  }

  async function handleRerunLLM() {
    const c = selectedCandidate.current;
    if (!c) {
      toast.error("Re-run only available after picking a program");
      return;
    }
    setLoading(true);
    try {
      const creds = platform === "hackerone" ? { token: apiToken } : undefined;
      const fresh = await fetchEngagement({ platform, handle: c.handle, url: c.url, credentials: creds, use_llm: true });
      setEditStageRules((prev) => ({ ...fresh.conditional_stages, ...prev }));
      toast.success("LLM pass complete — stage rules merged");
    } catch {
      // toast already shown
    } finally {
      setLoading(false);
    }
  }

  function handleApply() {
    if (!prefill) return;
    const finalPrefill: CampaignFormPrefill = {
      ...prefill,
      seed_targets: editSeeds.filter(Boolean),
      in_scope: editInScope.filter(Boolean),
      out_of_scope: editOutOfScope.filter(Boolean),
      rate_limit: editRateLimit,
      custom_headers: Object.fromEntries(
        editHeaders.filter((h) => h.key.trim()).map((h) => [h.key.trim(), h.value.trim()])
      ),
      conditional_stages: editStageRules,
    };
    onApply(finalPrefill);
  }

  function ListEditor({ items, onChange, placeholder }: {
    items: string[]; onChange: (v: string[]) => void; placeholder: string;
  }) {
    return (
      <div className="space-y-1">
        {items.map((item, i) => (
          <div key={i} className="flex gap-2">
            <input
              value={item}
              onChange={(e) => { const n = [...items]; n[i] = e.target.value; onChange(n); }}
              className="flex-1 rounded-md border border-border bg-bg-surface px-3 py-1.5 text-sm text-text-primary input-focus"
              placeholder={placeholder}
            />
            <button type="button" onClick={() => onChange(items.filter((_, j) => j !== i))}
              className="px-2 text-sm text-danger hover:text-danger/80">×</button>
          </div>
        ))}
        <button type="button" onClick={() => onChange([...items, ""])}
          className="text-xs text-accent hover:underline">+ Add</button>
      </div>
    );
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-end">
      <div className="absolute inset-0 bg-black/40" onClick={onClose} />
      <div className="relative z-10 flex h-full w-full max-w-xl flex-col bg-bg-surface shadow-2xl overflow-y-auto">
        <div className="flex items-center justify-between border-b border-border px-6 py-4">
          <h2 className="text-lg font-semibold text-text-primary">Find Engagement</h2>
          <button onClick={onClose} className="text-text-secondary hover:text-text-primary text-xl">×</button>
        </div>

        <div className="flex gap-2 px-6 pt-4 text-xs text-text-secondary">
          {(["Search", "Pick Program", "Review & Edit", "Confirm"] as const).map((label, i) => (
            <span key={label} className={`${step === i + 1 ? "text-accent font-semibold" : ""}`}>
              {i > 0 && <span className="mr-2">›</span>}{label}
            </span>
          ))}
        </div>

        <div className="flex-1 space-y-5 px-6 py-4">

          {step === 1 && (
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-text-secondary mb-1">Platform</label>
                <select value={platform} onChange={(e) => setPlatform(e.target.value as Platform)}
                  className="w-full rounded-md border border-border bg-bg-surface px-3 py-2 text-sm text-text-primary input-focus">
                  {PLATFORMS.map((p) => (
                    <option key={p} value={p}>{p.charAt(0).toUpperCase() + p.slice(1)}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-text-secondary mb-1">Company Name</label>
                <input value={companyName} onChange={(e) => setCompanyName(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleSearch()}
                  className="w-full rounded-md border border-border bg-bg-surface px-3 py-2 text-sm text-text-primary input-focus"
                  placeholder="e.g. Google, Shopify" />
              </div>
              {platform === "hackerone" && (
                <div>
                  <label className="block text-sm font-medium text-text-secondary mb-1">
                    HackerOne API Token <span className="text-xs text-text-secondary">(required)</span>
                  </label>
                  <input type="password" value={apiToken} onChange={(e) => setApiToken(e.target.value)}
                    autoComplete="off"
                    className="w-full rounded-md border border-border bg-bg-surface px-3 py-2 text-sm text-text-primary input-focus"
                    placeholder="Your H1 API token" />
                </div>
              )}
              <button onClick={handleSearch} disabled={loading}
                className="w-full rounded-md btn-launch px-4 py-2 text-sm disabled:opacity-50">
                {loading ? "Searching…" : "Search"}
              </button>
            </div>
          )}

          {step === 2 && (
            <div className="space-y-3">
              <p className="text-sm text-text-secondary">Multiple programs found — pick the right one:</p>
              {candidates.map((c) => (
                <button key={c.handle} onClick={() => handlePickCandidate(c)} disabled={loading}
                  className="w-full rounded-lg border border-border bg-bg-surface px-4 py-3 text-left hover:border-accent/60 disabled:opacity-50 transition-colors">
                  <p className="text-sm font-semibold text-text-primary">{c.name}</p>
                  <p className="text-xs text-text-secondary mt-0.5">{c.url}</p>
                </button>
              ))}
              {loading && <p className="text-sm text-text-secondary">Fetching program policy…</p>}
            </div>
          )}

          {step === 3 && prefill && (
            <div className="space-y-6">
              {prefill.parse_warnings.length > 0 && (
                <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 px-4 py-3 text-sm text-amber-600 dark:text-amber-400">
                  <strong>Parser warnings:</strong>
                  <ul className="mt-1 list-disc list-inside space-y-0.5">
                    {prefill.parse_warnings.map((w, i) => <li key={i}>{w}</li>)}
                  </ul>
                </div>
              )}
              <div>
                <label className="block text-sm font-medium text-text-secondary mb-2">Seed Targets</label>
                <ListEditor items={editSeeds} onChange={setEditSeeds} placeholder="example.com" />
              </div>
              <div>
                <label className="block text-sm font-medium text-text-secondary mb-2">In-Scope Patterns</label>
                <ListEditor items={editInScope} onChange={setEditInScope} placeholder="*.example.com" />
              </div>
              <div>
                <label className="block text-sm font-medium text-text-secondary mb-2">Out-of-Scope Patterns</label>
                <ListEditor items={editOutOfScope} onChange={setEditOutOfScope} placeholder="admin.example.com" />
              </div>
              <div>
                <label className="block text-sm font-medium text-text-secondary mb-1">Rate Limit (req/s)</label>
                <input type="number" value={editRateLimit} min={1} max={200}
                  onChange={(e) => setEditRateLimit(Number(e.target.value))}
                  className="w-32 rounded-md border border-border bg-bg-surface px-3 py-1.5 text-sm text-text-primary input-focus" />
              </div>
              <div>
                <label className="block text-sm font-medium text-text-secondary mb-2">Custom Headers</label>
                <div className="space-y-1">
                  {editHeaders.map((h, i) => (
                    <div key={i} className="flex gap-2">
                      <input value={h.key} placeholder="X-Header-Name"
                        onChange={(e) => { const n = [...editHeaders]; n[i] = { ...n[i], key: e.target.value }; setEditHeaders(n); }}
                        className="w-2/5 rounded-md border border-border bg-bg-surface px-2 py-1.5 text-sm text-text-primary input-focus" />
                      <input value={h.value} placeholder="value"
                        onChange={(e) => { const n = [...editHeaders]; n[i] = { ...n[i], value: e.target.value }; setEditHeaders(n); }}
                        className="flex-1 rounded-md border border-border bg-bg-surface px-2 py-1.5 text-sm text-text-primary input-focus" />
                      <button type="button" onClick={() => setEditHeaders(editHeaders.filter((_, j) => j !== i))}
                        className="px-2 text-sm text-danger hover:text-danger/80">×</button>
                    </div>
                  ))}
                  <button type="button" onClick={() => setEditHeaders([...editHeaders, { key: "", value: "" }])}
                    className="text-xs text-accent hover:underline">+ Add header</button>
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium text-text-secondary mb-2">Stage Rules</label>
                {Object.keys(editStageRules).length === 0 ? (
                  <p className="text-xs text-text-secondary">No stages flagged by policy parser.</p>
                ) : (
                  <div className="rounded-lg border border-border overflow-hidden">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="border-b border-border bg-bg-surface">
                          <th className="px-3 py-2 text-left text-xs font-medium text-text-secondary">Stage</th>
                          <th className="px-3 py-2 text-center text-xs font-medium text-text-secondary">Out of Scope</th>
                          <th className="px-3 py-2 text-center text-xs font-medium text-text-secondary">Chain Exception</th>
                          <th className="px-3 py-2"></th>
                        </tr>
                      </thead>
                      <tbody>
                        {Object.entries(editStageRules).map(([stage, rule]) => (
                          <tr key={stage} className="border-b border-border last:border-0">
                            <td className="px-3 py-2 text-text-primary font-mono text-xs">{stage}</td>
                            <td className="px-3 py-2 text-center">
                              <input type="checkbox" checked={rule.out_of_scope}
                                onChange={(e) => setEditStageRules((prev) => ({
                                  ...prev, [stage]: { ...rule, out_of_scope: e.target.checked }
                                }))} className="rounded border-border" />
                            </td>
                            <td className="px-3 py-2 text-center">
                              <input type="checkbox" checked={rule.chain_exception}
                                disabled={!rule.out_of_scope}
                                onChange={(e) => setEditStageRules((prev) => ({
                                  ...prev, [stage]: { ...rule, chain_exception: e.target.checked }
                                }))} className="rounded border-border disabled:opacity-40" />
                            </td>
                            <td className="px-3 py-2">
                              <button type="button" onClick={() => setEditStageRules((prev) => {
                                const n = { ...prev }; delete n[stage]; return n;
                              })} className="text-xs text-danger hover:text-danger/80">Remove</button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
                <div className="mt-2 flex gap-2">
                  <select value={addStage} onChange={(e) => setAddStage(e.target.value)}
                    className="flex-1 rounded-md border border-border bg-bg-surface px-2 py-1.5 text-sm text-text-primary input-focus">
                    <option value="">Add a stage…</option>
                    {ALL_STAGES.filter((s) => !(s in editStageRules)).map((s) => (
                      <option key={s} value={s}>{s}</option>
                    ))}
                  </select>
                  <button type="button" disabled={!addStage}
                    onClick={() => {
                      if (!addStage) return;
                      setEditStageRules((prev) => ({
                        ...prev, [addStage]: { out_of_scope: true, chain_exception: false, reason: "Added manually" }
                      }));
                      setAddStage("");
                    }}
                    className="rounded-md border border-border px-3 py-1.5 text-sm text-text-primary hover:border-accent/60 disabled:opacity-40">
                    Add
                  </button>
                </div>
              </div>
              <div>
                <div className="flex items-center justify-between mb-1">
                  <label className="text-sm font-medium text-text-secondary">Full Policy Guidelines</label>
                  <button type="button" onClick={() => setGuidelinesOpen(!guidelinesOpen)}
                    className="text-xs text-accent hover:underline">
                    {guidelinesOpen ? "Collapse" : "Expand"}
                  </button>
                </div>
                <p className="text-xs text-amber-600 dark:text-amber-400 mb-1">
                  Review the full policy below to catch anything the parser may have missed.
                </p>
                {guidelinesOpen && (
                  <pre className="rounded-lg border border-border bg-bg-base p-3 text-xs text-text-secondary whitespace-pre-wrap max-h-48 overflow-y-auto">
                    {prefill.guidelines || "(No policy text found)"}
                  </pre>
                )}
              </div>
              <button type="button" onClick={handleRerunLLM} disabled={loading}
                className="w-full rounded-md border border-border px-4 py-2 text-sm text-text-secondary hover:border-accent/60 disabled:opacity-50">
                {loading ? "Running LLM…" : "Re-run with LLM (deeper analysis)"}
              </button>
              <button type="button" onClick={() => setStep(4)}
                className="w-full rounded-md btn-launch px-4 py-2 text-sm">
                Review & Confirm →
              </button>
            </div>
          )}

          {step === 4 && prefill && (
            <div className="space-y-4">
              <p className="text-sm text-text-secondary">About to apply the following to the campaign form:</p>
              <ul className="text-sm text-text-primary space-y-1">
                <li><span className="font-medium">Program:</span> {prefill.program_name}</li>
                <li><span className="font-medium">Seed targets:</span> {editSeeds.filter(Boolean).length}</li>
                <li><span className="font-medium">In-scope patterns:</span> {editInScope.filter(Boolean).length}</li>
                <li><span className="font-medium">Out-of-scope patterns:</span> {editOutOfScope.filter(Boolean).length}</li>
                <li><span className="font-medium">Rate limit:</span> {editRateLimit} req/s</li>
                <li><span className="font-medium">Custom headers:</span> {editHeaders.filter((h) => h.key.trim()).length}</li>
                <li><span className="font-medium">Flagged stages:</span> {Object.keys(editStageRules).length}</li>
              </ul>
              <div className="flex gap-3">
                <button type="button" onClick={() => setStep(3)}
                  className="flex-1 rounded-md border border-border px-4 py-2 text-sm text-text-secondary hover:border-accent/60">
                  ← Back
                </button>
                <button type="button" onClick={handleApply}
                  className="flex-1 rounded-md btn-launch px-4 py-2 text-sm">
                  Apply to Campaign
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
