"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { toast } from "sonner";
import type { ScopeConfig, CredentialConfig } from "@/types/campaign";

export default function CampaignCreatorPage() {
  const router = useRouter();
  const [loading, setLoading] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [seedTargets, setSeedTargets] = useState<string[]>([""]);
  const [inScope, setInScope] = useState<string[]>([""]);
  const [outOfScope, setOutOfScope] = useState<string[]>([""]);
  const [rateLimit, setRateLimit] = useState(50);

  // Tester credentials
  const [hasTesterCreds, setHasTesterCreds] = useState(false);
  const [testerUsername, setTesterUsername] = useState("");
  const [testerPassword, setTesterPassword] = useState("");
  const [testerAuthType, setTesterAuthType] = useState<"form" | "basic" | "bearer" | "oauth">("form");
  const [testerLoginUrl, setTesterLoginUrl] = useState("");

  // Testing user
  const [hasTestingUser, setHasTestingUser] = useState(false);
  const [testingUsername, setTestingUsername] = useState("");
  const [testingEmail, setTestingEmail] = useState("");
  const [testingProfileUrl, setTestingProfileUrl] = useState("");

  const addSeedTarget = () => setSeedTargets([...seedTargets, ""]);
  const removeSeedTarget = (i: number) => setSeedTargets(seedTargets.filter((_, idx) => idx !== i));
  const updateSeedTarget = (i: number, val: string) => {
    const next = [...seedTargets];
    next[i] = val;
    setSeedTargets(next);
  };

  const addInScope = () => setInScope([...inScope, ""]);
  const removeInScope = (i: number) => setInScope(inScope.filter((_, idx) => idx !== i));
  const updateInScope = (i: number, val: string) => {
    const next = [...inScope];
    next[i] = val;
    setInScope(next);
  };

  const addOutOfScope = () => setOutOfScope([...outOfScope, ""]);
  const removeOutOfScope = (i: number) => setOutOfScope(outOfScope.filter((_, idx) => idx !== i));
  const updateOutOfScope = (i: number, val: string) => {
    const next = [...outOfScope];
    next[i] = val;
    setOutOfScope(next);
  };

  const validate = (): string | null => {
    const seeds = seedTargets.filter((s) => s.trim());
    if (seeds.length === 0) return "At least one seed target is required";
    const ins = inScope.filter((s) => s.trim());
    if (ins.length === 0) return "At least one in-scope pattern is required";
    if (hasTesterCreds && !hasTestingUser) return "If tester credentials provided, testing user is required";
    if (rateLimit < 1 || rateLimit > 200) return "Rate limit must be between 1 and 200";
    return null;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const err = validate();
    if (err) {
      toast.error(err);
      return;
    }

    setLoading(true);

    const scopeConfig: ScopeConfig = {
      in_scope: inScope.filter((s) => s.trim()),
      out_of_scope: outOfScope.filter((s) => s.trim()),
    };

    const credentialConfig: CredentialConfig = {
      tester: hasTesterCreds
        ? {
            username: testerUsername,
            password: testerPassword,
            auth_type: testerAuthType,
            login_url: testerLoginUrl || undefined,
          }
        : null,
      testing_user: hasTestingUser
        ? {
            username: testingUsername,
            email: testingEmail,
            profile_url: testingProfileUrl || undefined,
          }
        : null,
    };

    const payload = {
      name,
      description: description || null,
      seed_targets: seedTargets.filter((s) => s.trim()),
      scope_config: scopeConfig,
      credentials: credentialConfig,
      rate_limit: rateLimit,
    };

    try {
      const res = await fetch("/api/campaigns", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!res.ok) {
        const body = await res.text();
        throw new Error(body || "Failed to create campaign");
      }
      const data = await res.json();
      toast.success("Campaign created");
      router.push(`/campaign/${data.id}/overview`);
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : "Failed to create campaign");
    } finally {
      setLoading(false);
    }
  };

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
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
              className="mt-1 w-full rounded-md border border-border bg-bg-surface px-3 py-2 text-sm text-text-primary focus:border-accent-primary focus:outline-none"
              placeholder="My Bug Bounty Campaign"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-text-secondary">Description</label>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={3}
              className="mt-1 w-full rounded-md border border-border bg-bg-surface px-3 py-2 text-sm text-text-primary focus:border-accent-primary focus:outline-none"
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
                type="text"
                value={t}
                onChange={(e) => updateSeedTarget(i, e.target.value)}
                className="flex-1 rounded-md border border-border bg-bg-surface px-3 py-2 text-sm text-text-primary focus:border-accent-primary focus:outline-none"
                placeholder="example.com"
              />
              {seedTargets.length > 1 && (
                <button
                  type="button"
                  onClick={() => removeSeedTarget(i)}
                  className="px-3 py-2 text-sm text-red-400 hover:text-red-300"
                >
                  Remove
                </button>
              )}
            </div>
          ))}
          <button
            type="button"
            onClick={addSeedTarget}
            className="text-sm text-accent-primary hover:underline"
          >
            + Add seed target
          </button>
        </section>

        {/* Scope config */}
        <section className="space-y-4 rounded-lg border border-border p-4">
          <h2 className="text-lg font-semibold text-text-primary">Scope Configuration</h2>
          <div>
            <label className="block text-sm font-medium text-text-secondary">In-Scope Patterns</label>
            {inScope.map((s, i) => (
              <div key={i} className="flex gap-2 mt-1">
                <input
                  type="text"
                  value={s}
                  onChange={(e) => updateInScope(i, e.target.value)}
                  className="flex-1 rounded-md border border-border bg-bg-surface px-3 py-2 text-sm text-text-primary focus:border-accent-primary focus:outline-none"
                  placeholder="*.example.com"
                />
                {inScope.length > 1 && (
                  <button
                    type="button"
                    onClick={() => removeInScope(i)}
                    className="px-3 py-2 text-sm text-red-400 hover:text-red-300"
                  >
                    Remove
                  </button>
                )}
              </div>
            ))}
            <button
              type="button"
              onClick={addInScope}
              className="text-sm text-accent-primary hover:underline mt-2"
            >
              + Add in-scope pattern
            </button>
          </div>
          <div>
            <label className="block text-sm font-medium text-text-secondary">Out-of-Scope Patterns</label>
            {outOfScope.map((s, i) => (
              <div key={i} className="flex gap-2 mt-1">
                <input
                  type="text"
                  value={s}
                  onChange={(e) => updateOutOfScope(i, e.target.value)}
                  className="flex-1 rounded-md border border-border bg-bg-surface px-3 py-2 text-sm text-text-primary focus:border-accent-primary focus:outline-none"
                  placeholder="admin.example.com"
                />
                {outOfScope.length > 1 && (
                  <button
                    type="button"
                    onClick={() => removeOutOfScope(i)}
                    className="px-3 py-2 text-sm text-red-400 hover:text-red-300"
                  >
                    Remove
                  </button>
                )}
              </div>
            ))}
            <button
              type="button"
              onClick={addOutOfScope}
              className="text-sm text-accent-primary hover:underline mt-2"
            >
              + Add out-of-scope pattern
            </button>
          </div>
        </section>

        {/* Tester credentials */}
        <section className="space-y-4 rounded-lg border border-border p-4">
          <div className="flex items-center gap-2">
            <h2 className="text-lg font-semibold text-text-primary">Tester Credentials</h2>
            <input
              type="checkbox"
              checked={hasTesterCreds}
              onChange={(e) => setHasTesterCreds(e.target.checked)}
              className="rounded border-border"
            />
          </div>
          {hasTesterCreds && (
            <div className="space-y-3">
              <div>
                <label className="block text-sm font-medium text-text-secondary">Username</label>
                <input
                  type="text"
                  value={testerUsername}
                  onChange={(e) => setTesterUsername(e.target.value)}
                  className="mt-1 w-full rounded-md border border-border bg-bg-surface px-3 py-2 text-sm text-text-primary focus:border-accent-primary focus:outline-none"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-text-secondary">Password</label>
                <input
                  type="password"
                  value={testerPassword}
                  onChange={(e) => setTesterPassword(e.target.value)}
                  className="mt-1 w-full rounded-md border border-border bg-bg-surface px-3 py-2 text-sm text-text-primary focus:border-accent-primary focus:outline-none"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-text-secondary">Auth Type</label>
                <select
                  value={testerAuthType}
                  onChange={(e) => setTesterAuthType(e.target.value as "form" | "basic" | "bearer" | "oauth")}
                  className="mt-1 w-full rounded-md border border-border bg-bg-surface px-3 py-2 text-sm text-text-primary focus:border-accent-primary focus:outline-none"
                >
                  <option value="form">Form</option>
                  <option value="basic">Basic</option>
                  <option value="bearer">Bearer</option>
                  <option value="oauth">OAuth</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-text-secondary">Login URL</label>
                <input
                  type="text"
                  value={testerLoginUrl}
                  onChange={(e) => setTesterLoginUrl(e.target.value)}
                  className="mt-1 w-full rounded-md border border-border bg-bg-surface px-3 py-2 text-sm text-text-primary focus:border-accent-primary focus:outline-none"
                  placeholder="https://example.com/login"
                />
              </div>
            </div>
          )}
        </section>

        {/* Testing user */}
        <section className="space-y-4 rounded-lg border border-border p-4">
          <div className="flex items-center gap-2">
            <h2 className="text-lg font-semibold text-text-primary">Testing User</h2>
            <input
              type="checkbox"
              checked={hasTestingUser}
              onChange={(e) => setHasTestingUser(e.target.checked)}
              className="rounded border-border"
            />
          </div>
          {hasTestingUser && (
            <div className="space-y-3">
              <div>
                <label className="block text-sm font-medium text-text-secondary">Username</label>
                <input
                  type="text"
                  value={testingUsername}
                  onChange={(e) => setTestingUsername(e.target.value)}
                  className="mt-1 w-full rounded-md border border-border bg-bg-surface px-3 py-2 text-sm text-text-primary focus:border-accent-primary focus:outline-none"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-text-secondary">Email</label>
                <input
                  type="email"
                  value={testingEmail}
                  onChange={(e) => setTestingEmail(e.target.value)}
                  className="mt-1 w-full rounded-md border border-border bg-bg-surface px-3 py-2 text-sm text-text-primary focus:border-accent-primary focus:outline-none"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-text-secondary">Profile URL</label>
                <input
                  type="text"
                  value={testingProfileUrl}
                  onChange={(e) => setTestingProfileUrl(e.target.value)}
                  className="mt-1 w-full rounded-md border border-border bg-bg-surface px-3 py-2 text-sm text-text-primary focus:border-accent-primary focus:outline-none"
                  placeholder="https://example.com/profile"
                />
              </div>
            </div>
          )}
        </section>

        {/* Rate limit */}
        <section className="space-y-4 rounded-lg border border-border p-4">
          <h2 className="text-lg font-semibold text-text-primary">Rate Limit</h2>
          <input
            type="number"
            value={rateLimit}
            onChange={(e) => setRateLimit(Number(e.target.value))}
            min={1}
            max={200}
            className="w-32 rounded-md border border-border bg-bg-surface px-3 py-2 text-sm text-text-primary focus:border-accent-primary focus:outline-none"
          />
          <p className="text-xs text-text-secondary">Requests per second (1-200, default 50)</p>
        </section>

        <button
          type="submit"
          disabled={loading}
          className="w-full rounded-md bg-accent-primary px-4 py-2 text-sm font-medium text-white hover:bg-accent-primary/90 disabled:opacity-50"
        >
          {loading ? "Creating..." : "Create Campaign"}
        </button>
      </form>
    </div>
  );
}
