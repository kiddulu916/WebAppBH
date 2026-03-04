"use client";

import { useEffect, useRef, useState } from "react";
import { Bell } from "lucide-react";
import { api } from "@/lib/api";
import { useCampaignStore } from "@/stores/campaign";
import type { Alert } from "@/types/schema";

export default function AlertDropdown() {
  const { activeTarget, unreadAlerts, setUnreadAlerts, decrementUnreadAlerts } =
    useCampaignStore();
  const [open, setOpen] = useState(false);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const ref = useRef<HTMLDivElement>(null);

  // Close on outside click
  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, []);

  // Fetch unread count on mount and when target changes
  useEffect(() => {
    if (!activeTarget) return;
    api
      .getAlerts(activeTarget.id, false)
      .then((res) => setUnreadAlerts(res.alerts.length))
      .catch(() => {});
  }, [activeTarget, setUnreadAlerts]);

  // Fetch all alerts when dropdown opens
  useEffect(() => {
    if (!open || !activeTarget) return;
    api
      .getAlerts(activeTarget.id)
      .then((res) => setAlerts(res.alerts))
      .catch(() => {});
  }, [open, activeTarget]);

  async function markRead(alertId: number) {
    await api.markAlertRead(alertId);
    setAlerts((prev) =>
      prev.map((a) => (a.id === alertId ? { ...a, is_read: true } : a)),
    );
    decrementUnreadAlerts();
  }

  function timeAgo(iso: string): string {
    const diff = Date.now() - new Date(iso).getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return "just now";
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    return `${Math.floor(hrs / 24)}d ago`;
  }

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setOpen(!open)}
        className="relative rounded p-1.5 text-text-muted transition-colors hover:bg-bg-surface hover:text-text-primary"
      >
        <Bell className="h-4 w-4" />
        {unreadAlerts > 0 && (
          <span className="absolute -right-1 -top-1 flex h-4 min-w-4 items-center justify-center rounded-full bg-danger px-1 text-[10px] font-bold text-white">
            {unreadAlerts > 99 ? "99+" : unreadAlerts}
          </span>
        )}
      </button>

      {open && (
        <div className="absolute right-0 top-full mt-2 w-80 rounded-lg border border-border bg-bg-secondary shadow-lg">
          <div className="border-b border-border px-3 py-2">
            <span className="text-xs font-medium text-text-secondary">
              Alerts
            </span>
          </div>
          <div className="max-h-72 overflow-y-auto">
            {alerts.length === 0 ? (
              <p className="px-3 py-4 text-center text-xs text-text-muted">
                No alerts
              </p>
            ) : (
              alerts.map((alert) => (
                <div
                  key={alert.id}
                  className={`flex items-start gap-2 border-b border-border px-3 py-2.5 ${
                    alert.is_read ? "opacity-50" : ""
                  }`}
                >
                  <span
                    className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${
                      alert.alert_type === "CRITICAL_ALERT"
                        ? "bg-danger"
                        : "bg-warning"
                    }`}
                  />
                  <div className="min-w-0 flex-1">
                    <p className="text-xs font-medium text-text-primary">
                      {alert.alert_type}
                    </p>
                    <p className="truncate text-xs text-text-muted">
                      {alert.message}
                    </p>
                    <span className="text-[10px] text-text-muted">
                      {timeAgo(alert.created_at)}
                    </span>
                  </div>
                  {!alert.is_read && (
                    <button
                      onClick={() => markRead(alert.id)}
                      className="shrink-0 text-[10px] text-accent hover:underline"
                    >
                      Read
                    </button>
                  )}
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
}
