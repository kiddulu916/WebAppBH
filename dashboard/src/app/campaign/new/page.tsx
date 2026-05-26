"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { toast } from "sonner";
import { api } from "@/lib/api";
import type { ScopeConfig, CredentialConfig } from "@/types/schema";

export default function CampaignCreatorPage() {
  const router = useRouter();
  const [loading, setLoading] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [seedTargets, setSeedTargets] = useState<string[]>([""]);
  const [inScope, setInScope] = useState<string[]>([""]);
  const [outOfScope, setOutOfScope] = useState<string[]>([""]);
  const [rateLimit, setRateLimit] = useState(50);

  // Account 1 — Attacker/Tester
  const [hasAccount1, setHasAccount1] = useState(false);
  const [acct1Username, setAcct1Username] = useState("");
  const [acct1Password, setAcct1Password] = useState("");
  const [acct1AuthType, setAcct1AuthType] = useState<"form" | "basic" | "bearer" | "oauth">("form");
  const [acct1LoginUrl, setAcct1LoginUrl] = useState("");

  // Account 2 — Target User
  const [hasAccount2, setHasAccount2] = useState(false);
  const [acct2Username, setAcct2Username] = useState("");
  const [acct2Email, setAcct2Email] = useState("");
  const [acct2Password, setAcct2Password] = useState("");
  const [acct2AuthType, setAcct2AuthType] = useState<"form" | "basic" | "bearer" | "oauth">("form");
  const [acct2LoginUrl, setAcct2LoginUrl] = useState("");
  const [acct2ProfileUrl, setAcct2ProfileUrl] = useState("");

  const addSeedTarget = () => setSeedTargets([...seedTargets, ""]);
  const removeSeedTarget = (i: number) => setSeedTargets(seedTargets.filter((_, idx) => idx !== i));
  const updateSeedTarget = (i: number, val: string) => {
    const next = [...seedTargets]; next[i] = val; setSeedTargets(next);
  };

  const addInScope = () => setInScope([...inScope, ""]);
  const removeInScope = (i: number) => setInScope(inScope.filter((_, idx) => idx !== i));
  const updateInScope = (i: number, val: string) => {
    const next = [...inScope]; next[i] = val; setInScope(next);
  };

  const addOutOfScope = () => setOutOfScope([...outOfScope, ""]);
  const removeOutOfScope = (i: number) => setOutOfScope(outOfScope.filter((_, idx) => idx !== i));
  const updateOutOfScope = (i: number, val: string) => {
    const next = [...outOfScope]; next[i] = val; setOutOfScope(next);
  };

  const validate = (): string | null => {
    const seeds = seedTargets.filter((s) => s.trim());
    if (seeds.length === 0) return "At least one seed target is required";
    const ins = inScope.filter((s) => s.trim());
    if (ins.length === 0) return "At least one in-scope pattern is required";
    if (rateLimit < 1 || rateLimit > 200) return "Rate limit must be between 1 and 200";
    return null;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const err = validate();
    if (err) { toast.error(err); return; }

    setLoading(true);

    const scopeConfig: ScopeConfig = {
      in_scope: inScope.filter((s) => s.trim()),
      out_of_scope: outOfScope.filter((s) => s.trim()),
    };

    const testerCredentials: CredentialConfig["tester"] = hasAccount1
      ? { username: acct1Username, password: acct1Password, auth_type: acct1AuthType, login_url: acct1LoginUrl || undefined }
      : null;

    const testingUser: CredentialConfig["testing_user"] = hasAccount2
      ? {
          username: acct2Username,
          email: acct2Email,
          password: acct2Password || undefined,
          auth_type: acct2AuthType,
          login_url: acct2LoginUrl || undefined,
          profile_url: acct2ProfileUrl || undefined,
        }
      : null;

    try {
      const data = await api.createCampaign({
        name,
        description: description || undefined,
        scope_config: scopeConfig,
        rate_limit: rateLimit,
        tester_credentials: testerCredentials,
        testing_user: testingUser,
      });
      toast.success("Campaign created");
      router.push(`/campaign/${data.id}/overview`);
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : "Failed to create campaign");
    } finally {
      setLoading(false);
    }
  };

  const showWarning = hasAccount1 && !hasAccount2;

  return (
    <div className="max-w-3xl mx-auto space-y-8">
      <div>
        <h1 className="text-2xl font-bold text-text-primary">Create Campaign</h1>
        <p className="mt-1 text-sm text-text-secondary">
          Configure seed targets, scope, credentials, and rate limits.
        </p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Basic info */}
        <section className="space-y-4 rounded-lg border border-border p-4">
          <h2 className="text-lg font-semibold text-text-primary">Basic Info</h2>
          <div>
            <label className="block text-sm font-medium text-text-secondary">Name</label>
            <input
              type="text" value={name} onChange={(e) => setName(e.target.value)} required
              className="mt-1 w-full rounded-md border border-border bg-bg-surface px-3 py-2 text-sm text-text-primary input-focus"
              placeholder="My Bug Bounty Campaign"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-text-secondary">Description</label>
            <textarea
              value={description} onChange={(e) => setDescription(e.target.value)} rows={3}
              className="mt-1 w-full rounded-md border border-border bg-bg-surface px-3 py-2 text-sm text-text-primary input-focus"
              placeholder="Optional description"
            />
          </div>
        </section>

        {/* Seed targets */}
        <section className="space-y-4 rounded-lg border border-border p-4">
          <h2 className="text-lg font-semibold text-text-primary">Seed Targets</h2>
          {seedTargets.map((t, i) => (
            <div key={i} className="flex gap-2">
              <input
                type="text" value={t} onChange={(e) => updateSeedTarget(i, e.target.value)}
                className="flex-1 rounded-md border border-border bg-bg-surface px-3 py-2 text-sm text-text-primary input-focus"
                placeholder="example.com"
              />
              {seedTargets.length > 1 && (
                <button type="button" onClick={() => removeSeedTarget(i)} className="px-3 py-2 text-sm text-danger hover:text-danger/80">Remove</button>
              )}
            </div>
          ))}
          <button type="button" onClick={addSeedTarget} className="text-sm text-accent hover:underline">+ Add seed target</button>
        </section>

        {/* Scope config */}
        <section className="space-y-4 rounded-lg border border-border p-4">
          <h2 className="text-lg font-semibold text-text-primary">Scope Configuration</h2>
          <div>
            <label className="block text-sm font-medium text-text-secondary">In-Scope Patterns</label>
            {inScope.map((s, i) => (
              <div key={i} className="flex gap-2 mt-1">
                <input
                  type="text" value={s} onChange={(e) => updateInScope(i, e.target.value)}
                  className="flex-1 rounded-md border border-border bg-bg-surface px-3 py-2 text-sm text-text-primary input-focus"
                  placeholder="*.example.com"
                />
                {inScope.length > 1 && (
                  <button type="button" onClick={() => removeInScope(i)} className="px-3 py-2 text-sm text-danger hover:text-danger/80">Remove</button>
                )}
              </div>
            ))}
            <button type="button" onClick={addInScope} className="text-sm text-accent hover:underline mt-2">+ Add in-scope pattern</button>
          </div>
          <div>
            <label className="block text-sm font-medium text-text-secondary">Out-of-Scope Patterns</label>
            {outOfScope.map((s, i) => (
              <div key={i} className="flex gap-2 mt-1">
                <input
                  type="text" value={s} onChange={(e) => updateOutOfScope(i, e.target.value)}
                  className="flex-1 rounded-md border border-border bg-bg-surface px-3 py-2 text-sm text-text-primary input-focus"
                  placeholder="admin.example.com"
                />
                {outOfScope.length > 1 && (
                  <button type="button" onClick={() => removeOutOfScope(i)} className="px-3 py-2 text-sm text-danger hover:text-danger/80">Remove</button>
                )}
              </div>
            ))}
            <button type="button" onClick={addOutOfScope} className="text-sm text-accent hover:underline mt-2">+ Add out-of-scope pattern</button>
          </div>
        </section>

        {/* Account 1 — Attacker/Tester */}
        <section className="space-y-4 rounded-lg border border-border p-4">
          <div className="flex items-center gap-2">
            <input type="checkbox" checked={hasAccount1} onChange={(e) => setHasAccount1(e.target.checked)} className="rounded border-border" />
            <h2 className="text-lg font-semibold text-text-primary">Account 1 — Attacker/Tester</h2>
          </div>
          {hasAccount1 && (
            <div className="space-y-3">
              <div>
                <label className="block text-sm font-medium text-text-secondary">Username / Email</label>
                <input type="text" value={acct1Username} onChange={(e) => setAcct1Username(e.target.value)}
                  className="mt-1 w-full rounded-md border border-border bg-bg-surface px-3 py-2 text-sm text-text-primary input-focus" />
              </div>
              <div>
                <label className="block text-sm font-medium text-text-secondary">Password</label>
                <input type="password" value={acct1Password} onChange={(e) => setAcct1Password(e.target.value)}
                  className="mt-1 w-full rounded-md border border-border bg-bg-surface px-3 py-2 text-sm text-text-primary input-focus" />
              </div>
              <div>
                <label className="block text-sm font-medium text-text-secondary">Auth Type</label>
                <select value={acct1AuthType} onChange={(e) => setAcct1AuthType(e.target.value as "form" | "basic" | "bearer" | "oauth")}
                  className="mt-1 w-full rounded-md border border-border bg-bg-surface px-3 py-2 text-sm text-text-primary input-focus">
                  <option value="form">Form</option>
                  <option value="basic">Basic</option>
                  <option value="bearer">Bearer</option>
                  <option value="oauth">OAuth</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-text-secondary">Login URL</label>
                <input type="text" value={acct1LoginUrl} onChange={(e) => setAcct1LoginUrl(e.target.value)}
                  className="mt-1 w-full rounded-md border border-border bg-bg-surface px-3 py-2 text-sm text-text-primary input-focus"
                  placeholder="https://example.com/login" />
              </div>
            </div>
          )}
        </section>

        {/* Warning banner — shown when Account 1 is enabled but Account 2 is not */}
        {showWarning && (
          <div className="rounded-lg border border-amber-500/40 bg-amber-500/10 px-4 py-3 text-sm text-amber-600 dark:text-amber-400">
            <strong>Two accounts required for IDOR tests.</strong> WSTG-IDNT-03 and authorization tests
            (WSTG-AUTHZ) require both Account 1 and Account 2 to run de-provisioning and IDOR checks.
            If Account 2 is not provided, those tests will be skipped and recorded as informational findings.
          </div>
        )}

        {/* Account 2 — Target User */}
        <section className="space-y-4 rounded-lg border border-border p-4">
          <div className="flex items-center gap-2">
            <input type="checkbox" checked={hasAccount2} onChange={(e) => setHasAccount2(e.target.checked)} className="rounded border-border" />
            <h2 className="text-lg font-semibold text-text-primary">Account 2 — Target User</h2>
          </div>
          {hasAccount2 && (
            <div className="space-y-3">
              <div>
                <label className="block text-sm font-medium text-text-secondary">Username / Email</label>
                <input type="text" value={acct2Username} onChange={(e) => setAcct2Username(e.target.value)}
                  className="mt-1 w-full rounded-md border border-border bg-bg-surface px-3 py-2 text-sm text-text-primary input-focus" />
              </div>
              <div>
                <label className="block text-sm font-medium text-text-secondary">Email</label>
                <input type="email" value={acct2Email} onChange={(e) => setAcct2Email(e.target.value)}
                  className="mt-1 w-full rounded-md border border-border bg-bg-surface px-3 py-2 text-sm text-text-primary input-focus" />
              </div>
              <div>
                <label className="block text-sm font-medium text-text-secondary">Password</label>
                <input type="password" value={acct2Password} onChange={(e) => setAcct2Password(e.target.value)}
                  className="mt-1 w-full rounded-md border border-border bg-bg-surface px-3 py-2 text-sm text-text-primary input-focus" />
              </div>
              <div>
                <label className="block text-sm font-medium text-text-secondary">Auth Type</label>
                <select value={acct2AuthType} onChange={(e) => setAcct2AuthType(e.target.value as "form" | "basic" | "bearer" | "oauth")}
                  className="mt-1 w-full rounded-md border border-border bg-bg-surface px-3 py-2 text-sm text-text-primary input-focus">
                  <option value="form">Form</option>
                  <option value="basic">Basic</option>
                  <option value="bearer">Bearer</option>
                  <option value="oauth">OAuth</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-text-secondary">Login URL</label>
                <input type="text" value={acct2LoginUrl} onChange={(e) => setAcct2LoginUrl(e.target.value)}
                  className="mt-1 w-full rounded-md border border-border bg-bg-surface px-3 py-2 text-sm text-text-primary input-focus"
                  placeholder="https://example.com/login" />
              </div>
              <div>
                <label className="block text-sm font-medium text-text-secondary">Profile URL (optional)</label>
                <input type="text" value={acct2ProfileUrl} onChange={(e) => setAcct2ProfileUrl(e.target.value)}
                  className="mt-1 w-full rounded-md border border-border bg-bg-surface px-3 py-2 text-sm text-text-primary input-focus"
                  placeholder="https://example.com/users/victim" />
              </div>
            </div>
          )}
        </section>

        {/* Rate limit */}
        <section className="space-y-4 rounded-lg border border-border p-4">
          <h2 className="text-lg font-semibold text-text-primary">Rate Limit</h2>
          <input type="number" value={rateLimit} onChange={(e) => setRateLimit(Number(e.target.value))}
            min={1} max={200}
            className="w-32 rounded-md border border-border bg-bg-surface px-3 py-2 text-sm text-text-primary input-focus" />
          <p className="text-xs text-text-secondary">Requests per second (1–200, default 50)</p>
        </section>

        <button type="submit" disabled={loading} className="w-full rounded-md btn-launch px-4 py-2 text-sm disabled:opacity-50">
          {loading ? "Creating..." : "Create Campaign"}
        </button>
      </form>
    </div>
  );
}
