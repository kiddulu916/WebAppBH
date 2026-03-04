"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import {
  ChevronRight,
  ChevronLeft,
  Loader2,
  Globe,
  ShieldCheck,
  Settings,
} from "lucide-react";
import { api, type CreateTargetPayload } from "@/lib/api";
import { useCampaignStore } from "@/stores/campaign";

type Step = 0 | 1 | 2;

const STEP_TITLES = ["Target Info", "Scope Configuration", "Settings"] as const;
const STEP_ICONS = [Globe, ShieldCheck, Settings] as const;

export default function ScopeBuilder() {
  const router = useRouter();
  const setActiveTarget = useCampaignStore((s) => s.setActiveTarget);

  const [step, setStep] = useState<Step>(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  // Step 0 — target info
  const [companyName, setCompanyName] = useState("");
  const [baseDomain, setBaseDomain] = useState("");

  // Step 1 — scope
  const [inScopeDomains, setInScopeDomains] = useState("");
  const [outScopeDomains, setOutScopeDomains] = useState("");
  const [inScopeCidrs, setInScopeCidrs] = useState("");
  const [inScopeRegex, setInScopeRegex] = useState("");
  const [showOutOfScope, setShowOutOfScope] = useState(false);

  // Step 2 — settings
  const [customHeaders, setCustomHeaders] = useState("");
  const [rateLimit, setRateLimit] = useState("50");

  const canNext =
    step === 0 ? companyName.trim() && baseDomain.trim() : true;

  async function handleSubmit() {
    setLoading(true);
    setError("");

    const lines = (s: string) =>
      s.split("\n").map((l) => l.trim()).filter(Boolean);

    const parsedHeaders: Record<string, string> = {};
    try {
      if (customHeaders.trim()) {
        // Support "Key: Value" lines
        for (const line of lines(customHeaders)) {
          const idx = line.indexOf(":");
          if (idx > 0) {
            parsedHeaders[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
          }
        }
      }
    } catch {
      setError("Invalid custom headers format. Use 'Key: Value' per line.");
      setLoading(false);
      return;
    }

    const payload: CreateTargetPayload = {
      company_name: companyName.trim(),
      base_domain: baseDomain.trim(),
      target_profile: {
        in_scope_domains: lines(inScopeDomains),
        out_scope_domains: lines(outScopeDomains),
        in_scope_cidrs: lines(inScopeCidrs),
        in_scope_regex: lines(inScopeRegex),
        rate_limits: { pps: parseInt(rateLimit, 10) || 50 },
        custom_headers: parsedHeaders,
      },
    };

    try {
      const res = await api.createTarget(payload);
      setActiveTarget({
        id: res.target_id,
        company_name: res.company_name,
        base_domain: res.base_domain,
        target_profile: payload.target_profile ?? null,
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

  return (
    <div className="mx-auto max-w-2xl space-y-6">
      {/* Step indicator */}
      <div className="flex items-center justify-center gap-2">
        {STEP_TITLES.map((title, i) => {
          const Icon = STEP_ICONS[i];
          const active = i === step;
          const completed = i < step;
          return (
            <div key={title} className="flex items-center gap-2">
              {i > 0 && (
                <div
                  className={`h-px w-8 ${
                    completed ? "bg-accent" : "bg-border"
                  }`}
                />
              )}
              <button
                onClick={() => (i <= step ? setStep(i as Step) : null)}
                className={`flex items-center gap-1.5 rounded-full px-3 py-1.5 text-xs transition-colors ${
                  active
                    ? "bg-accent text-bg-primary"
                    : completed
                      ? "bg-bg-surface text-accent"
                      : "bg-bg-secondary text-text-muted"
                }`}
              >
                <Icon className="h-3.5 w-3.5" />
                {title}
              </button>
            </div>
          );
        })}
      </div>

      {/* Form card */}
      <div className="rounded-lg border border-border bg-bg-secondary p-6">
        {/* Step 0: Target Info */}
        {step === 0 && (
          <div className="space-y-4">
            <h2 className="text-lg font-semibold text-text-primary">
              Target Information
            </h2>
            <div>
              <label className="mb-1 block text-sm text-text-secondary">
                Company Name
              </label>
              <input
                type="text"
                value={companyName}
                onChange={(e) => setCompanyName(e.target.value)}
                placeholder="Acme Corp"
                className="w-full rounded-md border border-border bg-bg-tertiary px-3 py-2 text-sm text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none"
              />
            </div>
            <div>
              <label className="mb-1 block text-sm text-text-secondary">
                Base Domain
              </label>
              <input
                type="text"
                value={baseDomain}
                onChange={(e) => setBaseDomain(e.target.value)}
                placeholder="example.com"
                className="w-full rounded-md border border-border bg-bg-tertiary px-3 py-2 text-sm text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none"
              />
            </div>
          </div>
        )}

        {/* Step 1: Scope Configuration */}
        {step === 1 && (
          <div className="space-y-4">
            <h2 className="text-lg font-semibold text-text-primary">
              Scope Configuration
            </h2>
            <div>
              <label className="mb-1 block text-sm text-text-secondary">
                In-Scope Domains (one per line, supports wildcards)
              </label>
              <textarea
                value={inScopeDomains}
                onChange={(e) => setInScopeDomains(e.target.value)}
                placeholder={"*.example.com\napi.example.com"}
                rows={4}
                className="w-full rounded-md border border-border bg-bg-tertiary px-3 py-2 font-mono text-sm text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none"
              />
            </div>
            <div>
              <label className="mb-1 block text-sm text-text-secondary">
                In-Scope CIDRs / IPs (one per line)
              </label>
              <textarea
                value={inScopeCidrs}
                onChange={(e) => setInScopeCidrs(e.target.value)}
                placeholder={"10.0.0.0/8\n192.168.1.100"}
                rows={3}
                className="w-full rounded-md border border-border bg-bg-tertiary px-3 py-2 font-mono text-sm text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none"
              />
            </div>
            <div>
              <label className="mb-1 block text-sm text-text-secondary">
                In-Scope Regex Patterns (one per line)
              </label>
              <textarea
                value={inScopeRegex}
                onChange={(e) => setInScopeRegex(e.target.value)}
                placeholder={".*\\.example\\.com$"}
                rows={2}
                className="w-full rounded-md border border-border bg-bg-tertiary px-3 py-2 font-mono text-sm text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none"
              />
            </div>

            {/* Out of scope toggle */}
            <div className="flex items-center gap-3 rounded-md border border-border bg-bg-tertiary p-3">
              <button
                type="button"
                onClick={() => setShowOutOfScope(!showOutOfScope)}
                className={`relative h-5 w-9 rounded-full transition-colors ${
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
                Show Out-of-Scope (forbidden targets)
              </span>
            </div>

            {showOutOfScope && (
              <div>
                <label className="mb-1 block text-sm text-danger">
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
          </div>
        )}

        {/* Step 2: Settings */}
        {step === 2 && (
          <div className="space-y-4">
            <h2 className="text-lg font-semibold text-text-primary">
              Advanced Settings
            </h2>
            <div>
              <label className="mb-1 block text-sm text-text-secondary">
                Custom Headers (Key: Value, one per line)
              </label>
              <textarea
                value={customHeaders}
                onChange={(e) => setCustomHeaders(e.target.value)}
                placeholder={"Authorization: Bearer xxx\nX-Custom: value"}
                rows={4}
                className="w-full rounded-md border border-border bg-bg-tertiary px-3 py-2 font-mono text-sm text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none"
              />
            </div>
            <div>
              <label className="mb-1 block text-sm text-text-secondary">
                Rate Limit (Packets Per Second)
              </label>
              <input
                type="number"
                value={rateLimit}
                onChange={(e) => setRateLimit(e.target.value)}
                min={1}
                max={10000}
                className="w-32 rounded-md border border-border bg-bg-tertiary px-3 py-2 text-sm text-text-primary focus:border-accent focus:outline-none"
              />
            </div>
          </div>
        )}

        {/* Error */}
        {error && (
          <p className="mt-4 text-sm text-danger">{error}</p>
        )}

        {/* Navigation */}
        <div className="mt-6 flex items-center justify-between">
          <button
            onClick={() => setStep((step - 1) as Step)}
            disabled={step === 0}
            className="flex items-center gap-1 rounded-md px-4 py-2 text-sm text-text-secondary transition-colors hover:text-text-primary disabled:opacity-30"
          >
            <ChevronLeft className="h-4 w-4" />
            Back
          </button>

          {step < 2 ? (
            <button
              onClick={() => setStep((step + 1) as Step)}
              disabled={!canNext}
              className="flex items-center gap-1 rounded-md bg-accent px-4 py-2 text-sm font-medium text-bg-primary transition-colors hover:bg-accent-hover disabled:opacity-50"
            >
              Next
              <ChevronRight className="h-4 w-4" />
            </button>
          ) : (
            <button
              onClick={handleSubmit}
              disabled={loading}
              className="flex items-center gap-2 rounded-md bg-success px-5 py-2 text-sm font-medium text-bg-primary transition-colors hover:bg-success/90 disabled:opacity-50"
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
