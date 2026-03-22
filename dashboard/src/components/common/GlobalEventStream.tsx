"use client";

import { useCampaignStore } from "@/stores/campaign";
import { useEventStream } from "@/hooks/useEventStream";
import { useKeyboardShortcuts } from "@/hooks/useKeyboardShortcuts";

/**
 * Invisible component that lives in the layout.
 * Connects the SSE stream and registers keyboard shortcuts.
 * No UI rendered — just side effects.
 */
export default function GlobalEventStream() {
  const activeTarget = useCampaignStore((s) => s.activeTarget);
  useEventStream(activeTarget?.id ?? null);
  useKeyboardShortcuts();
  return null;
}
