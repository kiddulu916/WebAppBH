"use client";

import { useState, useMemo, useCallback, useEffect } from "react";
import { useRouter } from "next/navigation";
import {
  ChevronRight,
  ChevronLeft,
  Loader2,
  Crosshair,
  Shield,
  BookOpen,
  Layers,
  Rocket,
  Check,
  Eye,
  EyeOff,
} from "lucide-react";
import { api, type CreateTargetPayload } from "@/lib/api";
import { useCampaignStore } from "@/stores/campaign";
import PlaybookSelector from "@/components/campaign/PlaybookSelector";
import WorkflowBuilder, {
  initWorkflowState,
  DEFAULT_PHASES,
  type WorkflowState,
} from "@/components/campaign/WorkflowBuilder";
import RateLimitBuilder from "@/components/common/RateLimitBuilder";
import CustomHeaderBuilder, { type CustomHeader } from "@/components/common/CustomHeaderBuilder";

/* ------------------------------------------------------------------ */
/* Step definitions                                                    */
/* ------------------------------------------------------------------ */

type Step = 0 | 1 | 2 | 3 | 4;

const STEPS = [
  { title: "Target Intel", icon: Crosshair },
  { title: "Scope Rules", icon: Shield },
  { title: "Playbook", icon: BookOpen },
  { title: "Workflow", icon: Layers },
  { title: "Review & Launch", icon: Rocket },
] as const;

/* ------------------------------------------------------------------ */
/* Platforms                                                           */
/* ------------------------------------------------------------------ */

const PLATFORMS = ["HackerOne", "Bugcrowd", "Intigriti", "Custom"] as const;

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

function lines(s: string): string[] {
  return s
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean);
}

/* ------------------------------------------------------------------ */
/* Component                                                          */
/* ------------------------------------------------------------------ */

export default function ScopeBuilder() {
  const router = useRouter();
  const setActiveTarget = useCampaignStore((s) => s.setActiveTarget);

  const [step, setStep] = useState<Step>(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  /* ---- Step 0: Target Intel ---- */
  const [companyName, setCompanyName] = useState("");
  const [baseDomain, setBaseDomain] = useState("");
  const [platform, setPlatform] = useState<string>("HackerOne");
  const [notes, setNotes] = useState("");

  /* ---- Intel API Key status (read-only; keys are managed in Settings) ---- */
  const [apiKeyStatus, setApiKeyStatus] = useState<Record<string, boolean>>({
    shodan: false,
    securitytrails: false,
    censys: false,
  });

  useEffect(() => {
    api.getApiKeyStatus().then((res) => setApiKeyStatus(res.keys)).catch(() => {});
  }, []);

  /* ---- Inline API key editor ---- */
  const [editingKeys, setEditingKeys] = useState(false);
  const [savingKeys, setSavingKeys] = useState(false);
  const [shodanKey, setShodanKey] = useState("");
  const [securityTrailsKey, setSecurityTrailsKey] = useState("");
  const [censysId, setCensysId] = useState("");
  const [censysSecret, setCensysSecret] = useState("");
  const [showShodan, setShowShodan] = useState(false);
  const [showST, setShowST] = useState(false);
  const [showCensysId, setShowCensysId] = useState(false);
  const [showCensysSecret, setShowCensysSecret] = useState(false);

  /* ---- Step 1: Scope Rules ---- */
  const [inScopeDomains, setInScopeDomains] = useState("");
  const [inScopeCidrs, setInScopeCidrs] = useState("");
  const [inScopeRegex, setInScopeRegex] = useState("");
  const [showOutOfScope, setShowOutOfScope] = useState(false);
  const [outScopeDomains, setOutScopeDomains] = useState("");
  const [customHeaders, setCustomHeaders] = useState<CustomHeader[]>([]);

  /* ---- Step 2: Playbook ---- */
  const [playbook, setPlaybook] = useState("wide_recon");

  /* ---- Step 3: Workflow Builder ---- */
  const [workflow, setWorkflow] = useState<WorkflowState>(initWorkflowState);

  /* ---- Step 4: Review / Rate Limits ---- */
  const [rateLimitRules, setRateLimitRules] = useState<
    Array<{ amount: number; unit: string }>
  >([{ amount: 50, unit: "req/s" }]);

  async function handleSaveKeys() {
    if (!shodanKey.trim() && !securityTrailsKey.trim() && !censysId.trim() && !censysSecret.trim()) {
      handleCancelKeys();
      return;
    }
    setSavingKeys(true);
    try {
      const payload: {
        shodan_api_key?: string;
        securitytrails_api_key?: string;
        censys_api_id?: string;
        censys_api_secret?: string;
      } = {};
      if (shodanKey.trim()) payload.shodan_api_key = shodanKey.trim();
      if (securityTrailsKey.trim()) payload.securitytrails_api_key = securityTrailsKey.trim();
      if (censysId.trim()) payload.censys_api_id = censysId.trim();
      if (censysSecret.trim()) payload.censys_api_secret = censysSecret.trim();
      const res = await api.updateApiKeys(payload);
      setApiKeyStatus(res.keys ?? {});
      setEditingKeys(false);
      setShodanKey("");
      setSecurityTrailsKey("");
      setCensysId("");
      setCensysSecret("");
      setShowShodan(false);
      setShowST(false);
      setShowCensysId(false);
      setShowCensysSecret(false);
    } catch {
      // toast shown by api.request()
    } finally {
      setSavingKeys(false);
    }
  }

  function handleCancelKeys() {
    setEditingKeys(false);
    setShodanKey("");
    setSecurityTrailsKey("");
    setCensysId("");
    setCensysSecret("");
    setShowShodan(false);
    setShowST(false);
    setShowCensysId(false);
    setShowCensysSecret(false);
  }

  /* ---- Validation ---- */
  const canNext = useMemo(() => {
    if (step === 0) return companyName.trim() !== "" && baseDomain.trim() !== "";
    return true;
  }, [step, companyName, baseDomain]);

  /* ---- Derived counts for review ---- */
  const scopeCounts = useMemo(() => {
    const d = lines(inScopeDomains).length;
    const c = lines(inScopeCidrs).length;
    const r = lines(inScopeRegex).length;
    const o = lines(outScopeDomains).length;
    return { domains: d, cidrs: c, regex: r, outScope: o, total: d + c + r };
  }, [inScopeDomains, inScopeCidrs, inScopeRegex, outScopeDomains]);

  const workflowCounts = useMemo(() => {
    let ep = 0;
    let at = 0;
    let tt = 0;
    for (const p of DEFAULT_PHASES) {
      const set = workflow.phases[p.id];
      const count = set ? set.size : 0;
      tt += p.tools.length;
      at += count;
      if (count > 0) ep += 1;
    }
    return { enabledPhases: ep, totalPhases: DEFAULT_PHASES.length, activeTools: at, totalTools: tt };
  }, [workflow]);

  /* ---- Navigation ---- */
  const goBack = useCallback(() => {
    if (step > 0) setStep((step - 1) as Step);
  }, [step]);

  const goNext = useCallback(() => {
    if (step < 4 && canNext) setStep((step + 1) as Step);
  }, [step, canNext]);

  /* ---- Submit ---- */
  async function handleSubmit() {
    setLoading(true);
    setError("");

    const headersRecord = customHeaders
      .filter((h) => h.key.trim() !== "")
      .reduce<Record<string, string>>((acc, h) => {
        acc[h.key.trim()] = h.value;
        return acc;
      }, {});

    const payload: CreateTargetPayload = {
      company_name: companyName.trim(),
      base_domain: baseDomain.trim(),
      playbook,
      target_profile: {
        in_scope_domains: lines(inScopeDomains),
        out_scope_domains: lines(outScopeDomains),
        in_scope_cidrs: lines(inScopeCidrs),
        in_scope_regex: lines(inScopeRegex),
        rate_limits: rateLimitRules,
        ...(Object.keys(headersRecord).length > 0 && { custom_headers: headersRecord }),
      },
    };

    try {
      const res = await api.createTarget(payload);
      setActiveTarget({
        id: res.target_id,
        company_name: res.company_name,
        base_domain: res.base_domain,
        target_profile: payload.target_profile ?? null,
        last_playbook: payload.playbook ?? null,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      });
      router.push("/campaign/c2");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create target");
    } finally {
      setLoading(false);
    }
  }

  /* ---- Playbook display name ---- */
  const playbookLabel =
    { wide_recon: "Wide Recon", deep_webapp: "Deep WebApp", api_focused: "API Focused", cloud_first: "Cloud First" }[
      playbook
    ] ?? playbook;

  /* ================================================================ */
  /* Render                                                           */
  /* ================================================================ */

  return (
    <div data-testid="scope-builder" className="mx-auto max-w-4xl space-y-6">
      {/* ── Step indicator ── */}
      <nav className="flex items-center justify-center gap-0">
        {STEPS.map((s, i) => {
          const Icon = s.icon;
          const active = i === step;
          const completed = i < step;

          return (
            <div key={s.title} className="flex items-center">
              {/* Connecting line (before every step except the first) */}
              {i > 0 && (
                <div
                  className={`h-px w-10 transition-colors ${
                    completed ? "bg-neon-green" : "bg-border"
                  }`}
                />
              )}

              {/* Step circle + label */}
              <button
                data-testid={`scope-step-${i}`}
                type="button"
                onClick={() => {
                  if (i <= step) setStep(i as Step);
                }}
                disabled={i > step}
                className="flex flex-col items-center gap-1 group"
              >
                <div
                  className={`flex h-8 w-8 items-center justify-center rounded-full border-2 transition-all ${
                    active
                      ? "border-neon-orange bg-neon-orange text-bg-primary glow-orange"
                      : completed
                        ? "border-neon-green bg-neon-green/15 text-neon-green"
                        : "border-border bg-bg-secondary text-text-muted"
                  }`}
                >
                  {completed ? (
                    <Check className="h-3.5 w-3.5" />
                  ) : (
                    <Icon className="h-3.5 w-3.5" />
                  )}
                </div>
                <span
                  className={`text-[10px] font-medium transition-colors whitespace-nowrap ${
                    active
                      ? "text-neon-orange"
                      : completed
                        ? "text-neon-green"
                        : "text-text-muted"
                  }`}
                >
                  {s.title}
                </span>
              </button>
            </div>
          );
        })}
      </nav>

      {/* ── Form card ── */}
      <div className="rounded-lg border border-border bg-bg-secondary p-6 animate-fade-in">
        {/* ============================================================ */}
        {/* Step 0: Target Intel                                         */}
        {/* ============================================================ */}
        {step === 0 && (
          <div className="space-y-4 animate-fade-in">
            <h2 className="text-lg font-semibold text-text-primary flex items-center gap-2">
              <Crosshair className="h-4.5 w-4.5 text-neon-orange" />
              Target Intel
            </h2>

            <div>
              <label className="section-label mb-1.5 block">Company Name</label>
              <input
                data-testid="scope-company-input"
                type="text"
                value={companyName}
                onChange={(e) => setCompanyName(e.target.value)}
                placeholder="Acme Corp"
                className="w-full rounded-md border border-border bg-bg-tertiary px-3 py-2 text-sm text-text-primary placeholder:text-text-muted input-focus"
              />
            </div>

            <div>
              <label className="section-label mb-1.5 block">Base Domain</label>
              <input
                data-testid="scope-domain-input"
                type="text"
                value={baseDomain}
                onChange={(e) => setBaseDomain(e.target.value)}
                placeholder="example.com"
                className="w-full rounded-md border border-border bg-bg-tertiary px-3 py-2 font-mono text-sm text-text-primary placeholder:text-text-muted input-focus"
              />
            </div>

            <div>
              <label className="section-label mb-1.5 block">Platform</label>
              <select
                value={platform}
                onChange={(e) => setPlatform(e.target.value)}
                className="w-full rounded-md border border-border bg-bg-tertiary px-3 py-2 text-sm text-text-primary input-focus appearance-none cursor-pointer"
              >
                {PLATFORMS.map((p) => (
                  <option key={p} value={p}>
                    {p}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="section-label mb-1.5 block">Notes (optional)</label>
              <textarea
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                placeholder="Program rules, special instructions, or context..."
                rows={3}
                className="w-full rounded-md border border-border bg-bg-tertiary px-3 py-2 text-sm text-text-primary placeholder:text-text-muted input-focus"
              />
            </div>

            {/* ---- Intel Enrichment (inline key configuration) ---- */}
            <div className="rounded-md border border-border bg-bg-tertiary p-3 space-y-3">
              <div className="flex items-center justify-between">
                <span className="section-label">Intel Enrichment</span>
                {!editingKeys && (
                  <button
                    data-testid="intel-configure-btn"
                    type="button"
                    onClick={() => setEditingKeys(true)}
                    className="text-xs text-accent hover:underline"
                  >
                    Configure
                  </button>
                )}
              </div>

              <div className="flex flex-wrap gap-2">
                {Object.entries(apiKeyStatus).map(([key, configured]) => (
                  <span
                    key={key}
                    className={`rounded-full px-2 py-0.5 text-xs font-mono ${
                      configured
                        ? "bg-neon-green/15 text-neon-green"
                        : "bg-bg-surface text-text-muted"
                    }`}
                  >
                    {key}: {configured ? "configured" : "not set"}
                  </span>
                ))}
              </div>

              {editingKeys && (
                <div className="space-y-3 border-t border-border pt-3">
                  {/* Shodan */}
                  <div className="space-y-1">
                    <label className="text-xs font-medium text-text-secondary">Shodan API Key</label>
                    <div className="relative">
                      <input
                        data-testid="intel-shodan-input"
                        type={showShodan ? "text" : "password"}
                        value={shodanKey}
                        onChange={(e) => setShodanKey(e.target.value)}
                        placeholder="Leave blank to keep current"
                        className="w-full rounded border border-border bg-bg-surface px-2 py-1.5 pr-8 text-xs font-mono text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none"
                      />
                      <button
                        type="button"
                        onClick={() => setShowShodan(!showShodan)}
                        aria-label={showShodan ? "Hide key" : "Show key"}
                        className="absolute right-2 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-secondary"
                      >
                        {showShodan ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                      </button>
                    </div>
                  </div>

                  {/* SecurityTrails */}
                  <div className="space-y-1">
                    <label className="text-xs font-medium text-text-secondary">SecurityTrails API Key</label>
                    <div className="relative">
                      <input
                        data-testid="intel-st-input"
                        type={showST ? "text" : "password"}
                        value={securityTrailsKey}
                        onChange={(e) => setSecurityTrailsKey(e.target.value)}
                        placeholder="Leave blank to keep current"
                        className="w-full rounded border border-border bg-bg-surface px-2 py-1.5 pr-8 text-xs font-mono text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none"
                      />
                      <button
                        type="button"
                        onClick={() => setShowST(!showST)}
                        aria-label={showST ? "Hide key" : "Show key"}
                        className="absolute right-2 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-secondary"
                      >
                        {showST ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                      </button>
                    </div>
                  </div>

                  {/* Censys Organization ID */}
                  <div className="space-y-1">
                    <label className="text-xs font-medium text-text-secondary">Censys Organization ID</label>
                    <div className="relative">
                      <input
                        data-testid="intel-censys-id-input"
                        type={showCensysId ? "text" : "password"}
                        value={censysId}
                        onChange={(e) => setCensysId(e.target.value)}
                        placeholder="Leave blank to keep current"
                        className="w-full rounded border border-border bg-bg-surface px-2 py-1.5 pr-8 text-xs font-mono text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none"
                      />
                      <button
                        type="button"
                        onClick={() => setShowCensysId(!showCensysId)}
                        aria-label={showCensysId ? "Hide key" : "Show key"}
                        className="absolute right-2 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-secondary"
                      >
                        {showCensysId ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                      </button>
                    </div>
                  </div>

                  {/* Censys API Key */}
                  <div className="space-y-1">
                    <label className="text-xs font-medium text-text-secondary">Censys API Key</label>
                    <div className="relative">
                      <input
                        data-testid="intel-censys-secret-input"
                        type={showCensysSecret ? "text" : "password"}
                        value={censysSecret}
                        onChange={(e) => setCensysSecret(e.target.value)}
                        placeholder="Leave blank to keep current"
                        className="w-full rounded border border-border bg-bg-surface px-2 py-1.5 pr-8 text-xs font-mono text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none"
                      />
                      <button
                        type="button"
                        onClick={() => setShowCensysSecret(!showCensysSecret)}
                        aria-label={showCensysSecret ? "Hide key" : "Show key"}
                        className="absolute right-2 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-secondary"
                      >
                        {showCensysSecret ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                      </button>
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex justify-end gap-2 pt-1">
                    <button
                      data-testid="intel-cancel-btn"
                      type="button"
                      onClick={handleCancelKeys}
                      className="rounded px-3 py-1.5 text-xs text-text-muted hover:bg-bg-surface"
                    >
                      Cancel
                    </button>
                    <button
                      data-testid="intel-save-btn"
                      type="button"
                      onClick={handleSaveKeys}
                      disabled={savingKeys}
                      className="rounded-md bg-accent px-4 py-1.5 text-xs font-medium text-white transition-colors hover:bg-accent/90 disabled:opacity-50"
                    >
                      {savingKeys ? "Saving..." : "Save Keys"}
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ============================================================ */}
        {/* Step 1: Scope Rules                                          */}
        {/* ============================================================ */}
        {step === 1 && (
          <div className="space-y-4 animate-fade-in">
            <h2 className="text-lg font-semibold text-text-primary flex items-center gap-2">
              <Shield className="h-4.5 w-4.5 text-neon-blue" />
              Scope Rules
            </h2>

            <div>
              <label className="section-label mb-1.5 block">
                In-Scope Domains (one per line, supports wildcards)
              </label>
              <textarea
                value={inScopeDomains}
                onChange={(e) => setInScopeDomains(e.target.value)}
                placeholder={"*.example.com\napi.example.com"}
                rows={4}
                className="w-full rounded-md border border-border bg-bg-tertiary px-3 py-2 font-mono text-sm text-text-primary placeholder:text-text-muted input-focus"
              />
            </div>

            <div>
              <label className="section-label mb-1.5 block">
                In-Scope CIDRs / IPs (one per line)
              </label>
              <textarea
                value={inScopeCidrs}
                onChange={(e) => setInScopeCidrs(e.target.value)}
                placeholder={"10.0.0.0/8\n192.168.1.100"}
                rows={3}
                className="w-full rounded-md border border-border bg-bg-tertiary px-3 py-2 font-mono text-sm text-text-primary placeholder:text-text-muted input-focus"
              />
            </div>

            <div>
              <label className="section-label mb-1.5 block">
                In-Scope Regex Patterns (one per line)
              </label>
              <textarea
                value={inScopeRegex}
                onChange={(e) => setInScopeRegex(e.target.value)}
                placeholder={".*\\.example\\.com$"}
                rows={2}
                className="w-full rounded-md border border-border bg-bg-tertiary px-3 py-2 font-mono text-sm text-text-primary placeholder:text-text-muted input-focus"
              />
            </div>

            {/* Out-of-scope toggle */}
            <div className="flex items-center gap-3 rounded-md border border-border bg-bg-tertiary p-3">
              <button
                type="button"
                onClick={() => setShowOutOfScope(!showOutOfScope)}
                className={`relative h-5 w-9 shrink-0 rounded-full transition-colors ${
                  showOutOfScope ? "bg-danger" : "bg-border-accent"
                }`}
              >
                <span
                  className={`absolute top-0.5 left-0.5 h-4 w-4 rounded-full bg-white transition-transform ${
                    showOutOfScope ? "translate-x-4" : ""
                  }`}
                />
              </button>
              <span className="text-sm text-text-secondary">
                Define out-of-scope (forbidden targets)
              </span>
            </div>

            {showOutOfScope && (
              <div className="animate-fade-in">
                <label className="section-label mb-1.5 block text-danger">
                  Out-of-Scope Domains (one per line)
                </label>
                <textarea
                  value={outScopeDomains}
                  onChange={(e) => setOutScopeDomains(e.target.value)}
                  placeholder={"payments.example.com\ninternal.example.com"}
                  rows={3}
                  className="w-full rounded-md border border-danger/30 bg-bg-tertiary px-3 py-2 font-mono text-sm text-text-primary placeholder:text-text-muted focus:border-danger focus:outline-none"
                />
              </div>
            )}

            <div className="border-t border-border pt-4">
              <RateLimitBuilder
                rules={rateLimitRules}
                onChange={setRateLimitRules}
                label="Campaign Rate Limits"
              />
            </div>
            <div className="border-t border-border pt-4">
              <CustomHeaderBuilder
                headers={customHeaders}
                onChange={setCustomHeaders}
              />
            </div>
          </div>
        )}

        {/* ============================================================ */}
        {/* Step 2: Playbook                                             */}
        {/* ============================================================ */}
        {step === 2 && (
          <div className="space-y-4 animate-fade-in">
            <h2 className="text-lg font-semibold text-text-primary flex items-center gap-2">
              <BookOpen className="h-4.5 w-4.5 text-neon-orange" />
              Campaign Playbook
            </h2>
            <PlaybookSelector value={playbook} onChange={setPlaybook} />
          </div>
        )}

        {/* ============================================================ */}
        {/* Step 3: Workflow Builder                                      */}
        {/* ============================================================ */}
        {step === 3 && (
          <div className="space-y-4 animate-fade-in">
            <h2 className="text-lg font-semibold text-text-primary flex items-center gap-2">
              <Layers className="h-4.5 w-4.5 text-neon-blue" />
              Workflow Builder
            </h2>
            <WorkflowBuilder value={workflow} onChange={setWorkflow} />
          </div>
        )}

        {/* ============================================================ */}
        {/* Step 4: Review & Launch                                      */}
        {/* ============================================================ */}
        {step === 4 && (
          <div className="space-y-5 animate-fade-in">
            <h2 className="text-lg font-semibold text-text-primary flex items-center gap-2">
              <Rocket className="h-4.5 w-4.5 text-neon-green" />
              Review & Launch
            </h2>

            {/* Review grid */}
            <div className="space-y-3">
              {/* Target */}
              <div className="rounded-md border border-border bg-bg-tertiary p-3">
                <span className="section-label">Target</span>
                <div className="mt-1.5 space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-text-muted">Company</span>
                    <span className="font-mono text-xs text-text-primary">{companyName}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-text-muted">Domain</span>
                    <span className="font-mono text-xs text-neon-orange">{baseDomain}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-text-muted">Platform</span>
                    <span className="text-xs text-text-secondary">{platform}</span>
                  </div>
                </div>
              </div>

              {/* Scope */}
              <div className="rounded-md border border-border bg-bg-tertiary p-3">
                <span className="section-label">Scope</span>
                <div className="mt-1.5 space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-text-muted">In-scope domains</span>
                    <span className="font-mono text-xs text-neon-green">{scopeCounts.domains}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-text-muted">CIDRs</span>
                    <span className="font-mono text-xs text-neon-blue">{scopeCounts.cidrs}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-text-muted">Regex patterns</span>
                    <span className="font-mono text-xs text-text-secondary">{scopeCounts.regex}</span>
                  </div>
                  {scopeCounts.outScope > 0 && (
                    <div className="flex items-center justify-between">
                      <span className="text-xs text-danger">Out-of-scope</span>
                      <span className="font-mono text-xs text-danger">{scopeCounts.outScope}</span>
                    </div>
                  )}
                  <div className="flex items-center justify-between border-t border-border pt-1">
                    <span className="text-xs text-text-muted">Total rules</span>
                    <span className="font-mono text-xs font-semibold text-text-primary">
                      {scopeCounts.total}
                    </span>
                  </div>
                </div>
              </div>

              {/* Playbook + Workflow */}
              <div className="rounded-md border border-border bg-bg-tertiary p-3">
                <span className="section-label">Playbook & Workflow</span>
                <div className="mt-1.5 space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-text-muted">Playbook</span>
                    <span className="text-xs font-semibold text-neon-orange">{playbookLabel}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-text-muted">Phases enabled</span>
                    <span className="font-mono text-xs text-neon-green">
                      {workflowCounts.enabledPhases}/{workflowCounts.totalPhases}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-text-muted">Active tools</span>
                    <span className="font-mono text-xs text-neon-blue">
                      {workflowCounts.activeTools}/{workflowCounts.totalTools}
                    </span>
                  </div>
                </div>
              </div>

              {/* Execution */}
              <div className="rounded-md border border-border bg-bg-tertiary p-3">
                <span className="section-label">Execution</span>
                <div className="mt-1.5 space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-text-muted">Rate limits</span>
                    <span className="font-mono text-xs text-text-secondary">
                      {rateLimitRules.map((r) => `${r.amount} ${r.unit}`).join(", ")}
                    </span>
                  </div>
                  {customHeaders.filter((h) => h.key.trim() !== "").length > 0 && (
                    <div className="flex items-center justify-between">
                      <span className="text-xs text-text-muted">Custom headers</span>
                      <span
                        data-testid="review-custom-headers-count"
                        className="font-mono text-xs text-neon-blue"
                      >
                        {customHeaders.filter((h) => h.key.trim() !== "").length}
                      </span>
                    </div>
                  )}
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-text-muted">Estimated time</span>
                    <span className="font-mono text-xs text-text-muted">--:--</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ── Error ── */}
        {error && <p className="mt-4 text-sm text-danger">{error}</p>}

        {/* ── Navigation ── */}
        <div className="mt-6 flex items-center justify-between">
          <button
            data-testid="scope-back-btn"
            type="button"
            onClick={goBack}
            disabled={step === 0}
            className="flex items-center gap-1 rounded-md px-4 py-2 text-sm text-text-secondary transition-colors hover:text-text-primary disabled:opacity-30"
          >
            <ChevronLeft className="h-4 w-4" />
            Back
          </button>

          {step < 4 ? (
            <button
              data-testid="scope-next-btn"
              type="button"
              onClick={goNext}
              disabled={!canNext}
              className="flex items-center gap-1 rounded-md bg-neon-orange px-4 py-2 text-sm font-semibold text-bg-primary transition-colors hover:bg-neon-orange-dim disabled:opacity-50"
            >
              Next
              <ChevronRight className="h-4 w-4" />
            </button>
          ) : (
            <button
              data-testid="scope-submit-btn"
              type="button"
              onClick={handleSubmit}
              disabled={loading}
              className="btn-launch flex items-center gap-2 rounded-md px-6 py-2.5 text-sm"
            >
              {loading && <Loader2 className="h-4 w-4 animate-spin" />}
              Launch Campaign
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
