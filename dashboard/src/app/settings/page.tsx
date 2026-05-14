"use client";

import { useEffect, useState } from "react";
import {
  Settings,
  Key,
  Server,
  Database,
  Shield,
  Check,
  X,
  Eye,
  EyeOff,
} from "lucide-react";
import { api } from "@/lib/api";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8001";

export default function SettingsPage() {
  return (
    <div className="mx-auto max-w-3xl space-y-6 animate-fade-in">
      <div>
        <h1 className="flex items-center gap-3 text-2xl font-bold text-text-primary">
          <Settings className="h-5 w-5 text-neon-orange" />
          Settings
        </h1>
        <p className="mt-1 text-sm text-text-secondary">
          Global configuration for the WebAppBH framework
        </p>
      </div>

      <ConnectionStatus />
      <ApiKeysSection />
    </div>
  );
}

/* ── Connection Status ── */

function ConnectionStatus() {
  const [apiOk, setApiOk] = useState<boolean | null>(null);
  const [dbOk, setDbOk] = useState<boolean | null>(null);
  const [redisOk, setRedisOk] = useState<boolean | null>(null);

  useEffect(() => {
    // Check API by hitting a lightweight endpoint
    api
      .getQueueHealth()
      .then(() => {
        setApiOk(true);
        setDbOk(true); // if API responds, DB is up
        setRedisOk(true); // queue_health uses Redis
      })
      .catch(() => {
        setApiOk(false);
        setDbOk(false);
        setRedisOk(false);
      });
  }, []);

  return (
    <div className="rounded-lg border border-border bg-bg-secondary p-5">
      <p className="section-label mb-3">Infrastructure</p>
      <div className="grid grid-cols-3 gap-4">
        <StatusItem
          icon={<Server className="h-4 w-4" />}
          label="API"
          detail={API_URL}
          status={apiOk}
        />
        <StatusItem
          icon={<Database className="h-4 w-4" />}
          label="PostgreSQL"
          detail="asyncpg"
          status={dbOk}
        />
        <StatusItem
          icon={<Shield className="h-4 w-4" />}
          label="Redis"
          detail="Streams"
          status={redisOk}
        />
      </div>
    </div>
  );
}

function StatusItem({
  icon,
  label,
  detail,
  status,
}: {
  icon: React.ReactNode;
  label: string;
  detail: string;
  status: boolean | null;
}) {
  return (
    <div className="flex items-center gap-3 rounded-md border border-border bg-bg-tertiary px-3 py-2.5">
      <div className="text-text-muted">{icon}</div>
      <div className="flex-1 min-w-0">
        <p className="text-xs font-medium text-text-primary">{label}</p>
        <p className="truncate text-[10px] font-mono text-text-muted">
          {detail}
        </p>
      </div>
      {status === null && (
        <span className="h-2 w-2 rounded-full bg-text-muted animate-pulse" />
      )}
      {status === true && (
        <Check className="h-3.5 w-3.5 text-neon-green" />
      )}
      {status === false && (
        <X className="h-3.5 w-3.5 text-danger" />
      )}
    </div>
  );
}

/* ── API Keys ── */

function ApiKeysSection() {
  const [keys, setKeys] = useState<Record<string, boolean>>({});
  const [editing, setEditing] = useState(false);
  const [shodanKey, setShodanKey] = useState("");
  const [securityTrailsKey, setSecurityTrailsKey] = useState("");
  const [censysId, setCensysId] = useState("");
  const [censysSecret, setCensysSecret] = useState("");
  const [saving, setSaving] = useState(false);
  const [showShodan, setShowShodan] = useState(false);
  const [showST, setShowST] = useState(false);
  const [showCensysId, setShowCensysId] = useState(false);
  const [showCensysSecret, setShowCensysSecret] = useState(false);

  useEffect(() => {
    api
      .getApiKeyStatus()
      .then((res) => setKeys(res.keys ?? {}))
      .catch(() => {});
  }, []);

  async function handleSave() {
    setSaving(true);
    try {
      const payload: Record<string, string> = {};
      if (shodanKey.trim()) payload.shodan_api_key = shodanKey.trim();
      if (securityTrailsKey.trim())
        payload.securitytrails_api_key = securityTrailsKey.trim();
      if (censysId.trim()) payload.censys_api_id = censysId.trim();
      if (censysSecret.trim()) payload.censys_api_secret = censysSecret.trim();
      const res = await api.updateApiKeys(payload);
      setKeys(res.keys ?? {});
      setEditing(false);
      setShodanKey("");
      setSecurityTrailsKey("");
      setCensysId("");
      setCensysSecret("");
    } catch {
      // toast shown by api.request()
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="rounded-lg border border-border bg-bg-secondary p-5">
      <div className="flex items-center justify-between">
        <p className="section-label">API Keys</p>
        {!editing && (
          <button
            onClick={() => setEditing(true)}
            className="text-xs text-accent hover:underline"
          >
            Configure
          </button>
        )}
      </div>
      <p className="mt-1 text-xs text-text-muted">
        Third-party keys for intel enrichment (Shodan, SecurityTrails, Censys)
      </p>

      {/* Current status */}
      <div className="mt-3 space-y-2">
        {Object.entries(keys).map(([name, configured]) => (
          <div
            key={name}
            className="flex items-center justify-between rounded-md border border-border bg-bg-tertiary px-3 py-2"
          >
            <div className="flex items-center gap-2">
              <Key className="h-3.5 w-3.5 text-text-muted" />
              <span className="text-xs font-mono text-text-primary">
                {name}
              </span>
            </div>
            <span
              className={`text-[10px] font-medium ${configured ? "text-neon-green" : "text-text-muted"}`}
            >
              {configured ? "Configured" : "Not set"}
            </span>
          </div>
        ))}
        {Object.keys(keys).length === 0 && !editing && (
          <p className="text-xs text-text-muted italic">
            Could not fetch key status
          </p>
        )}
      </div>

      {/* Edit form */}
      {editing && (
        <div className="mt-4 space-y-3 border-t border-border pt-4">
          <div className="space-y-1">
            <label className="text-xs font-medium text-text-secondary">
              Shodan API Key
            </label>
            <div className="relative">
              <input
                type={showShodan ? "text" : "password"}
                value={shodanKey}
                onChange={(e) => setShodanKey(e.target.value)}
                placeholder="Leave blank to keep current"
                className="w-full rounded border border-border bg-bg-tertiary px-2 py-1.5 pr-8 text-xs font-mono text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none"
              />
              <button
                type="button"
                onClick={() => setShowShodan(!showShodan)}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-secondary"
              >
                {showShodan ? (
                  <EyeOff className="h-3.5 w-3.5" />
                ) : (
                  <Eye className="h-3.5 w-3.5" />
                )}
              </button>
            </div>
          </div>
          <div className="space-y-1">
            <label className="text-xs font-medium text-text-secondary">
              SecurityTrails API Key
            </label>
            <div className="relative">
              <input
                type={showST ? "text" : "password"}
                value={securityTrailsKey}
                onChange={(e) => setSecurityTrailsKey(e.target.value)}
                placeholder="Leave blank to keep current"
                className="w-full rounded border border-border bg-bg-tertiary px-2 py-1.5 pr-8 text-xs font-mono text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none"
              />
              <button
                type="button"
                onClick={() => setShowST(!showST)}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-secondary"
              >
                {showST ? (
                  <EyeOff className="h-3.5 w-3.5" />
                ) : (
                  <Eye className="h-3.5 w-3.5" />
                )}
              </button>
            </div>
          </div>
          <div className="space-y-1">
            <label className="text-xs font-medium text-text-secondary">
              Censys Organization ID
            </label>
            <div className="relative">
              <input
                type={showCensysId ? "text" : "password"}
                value={censysId}
                onChange={(e) => setCensysId(e.target.value)}
                placeholder="Leave blank to keep current"
                className="w-full rounded border border-border bg-bg-tertiary px-2 py-1.5 pr-8 text-xs font-mono text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none"
              />
              <button
                type="button"
                onClick={() => setShowCensysId(!showCensysId)}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-secondary"
              >
                {showCensysId ? (
                  <EyeOff className="h-3.5 w-3.5" />
                ) : (
                  <Eye className="h-3.5 w-3.5" />
                )}
              </button>
            </div>
          </div>
          <div className="space-y-1">
            <label className="text-xs font-medium text-text-secondary">
              Censys API Key
            </label>
            <div className="relative">
              <input
                type={showCensysSecret ? "text" : "password"}
                value={censysSecret}
                onChange={(e) => setCensysSecret(e.target.value)}
                placeholder="Leave blank to keep current"
                className="w-full rounded border border-border bg-bg-tertiary px-2 py-1.5 pr-8 text-xs font-mono text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none"
              />
              <button
                type="button"
                onClick={() => setShowCensysSecret(!showCensysSecret)}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-secondary"
              >
                {showCensysSecret ? (
                  <EyeOff className="h-3.5 w-3.5" />
                ) : (
                  <Eye className="h-3.5 w-3.5" />
                )}
              </button>
            </div>
          </div>
          <div className="flex justify-end gap-2">
            <button
              onClick={() => {
                setEditing(false);
                setShodanKey("");
                setSecurityTrailsKey("");
                setCensysId("");
                setCensysSecret("");
              }}
              className="rounded px-3 py-1.5 text-xs text-text-muted hover:bg-bg-surface"
            >
              Cancel
            </button>
            <button
              onClick={handleSave}
              disabled={saving}
              className="rounded-md bg-accent px-4 py-1.5 text-xs font-medium text-white transition-colors hover:bg-accent/90 disabled:opacity-50"
            >
              {saving ? "Saving..." : "Save Keys"}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
