"use client";

import { useEffect, useState } from "react";
import { ShieldAlert, Loader2 } from "lucide-react";
import { api } from "@/lib/api";
import { useCampaignStore } from "@/stores/campaign";

type CheckState = "checking" | "connected" | "failed";

export default function SystemCheck({ children }: { children: React.ReactNode }) {
  const [state, setState] = useState<CheckState>("checking");
  const [error, setError] = useState("");
  const setConnected = useCampaignStore((s) => s.setConnected);

  useEffect(() => {
    let cancelled = false;

    async function check() {
      try {
        await api.getStatus();
        if (!cancelled) {
          setState("connected");
          setConnected(true);
        }
      } catch (err) {
        if (!cancelled) {
          setState("failed");
          setConnected(false);
          setError(err instanceof Error ? err.message : "Connection failed");
        }
      }
    }

    check();
    return () => { cancelled = true; };
  }, [setConnected]);

  if (state === "checking") {
    return (
      <div className="flex h-screen items-center justify-center bg-bg-primary">
        <div className="flex flex-col items-center gap-4">
          <Loader2 className="h-8 w-8 animate-spin text-accent" />
          <p className="text-sm text-text-secondary">
            Connecting to Orchestrator...
          </p>
        </div>
      </div>
    );
  }

  if (state === "failed") {
    return (
      <div className="flex h-screen items-center justify-center bg-bg-primary">
        <div className="flex flex-col items-center gap-4 rounded-lg border border-danger/30 bg-bg-secondary p-8">
          <ShieldAlert className="h-10 w-10 text-danger" />
          <h2 className="text-lg font-semibold text-text-primary">
            System Check Failed
          </h2>
          <p className="max-w-sm text-center text-sm text-text-secondary">
            {error || "Unable to reach the orchestrator. Ensure it is running and the API key is configured."}
          </p>
          <button
            onClick={() => { setState("checking"); setError(""); }}
            className="mt-2 rounded-md bg-accent px-4 py-2 text-sm font-medium text-bg-primary transition-colors hover:bg-accent-hover"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  return <>{children}</>;
}
