"use client";

import { useState, useEffect, useCallback } from "react";
import { X, ChevronRight, ChevronLeft, Shield } from "lucide-react";
import { useUIStore } from "@/stores/ui";

const TOUR_STEPS = [
  {
    title: "Welcome to WebAppBH",
    description: "Your command center for bug bounty hunting. Let's take a quick tour.",
    selector: null,
  },
  {
    title: "Start a Campaign",
    description: "Create a new campaign by selecting a target, scope, and playbook.",
    selector: '[href="/campaign"]',
  },
  {
    title: "C2 Console",
    description: "Monitor workers, assets, and events in real-time as your campaign runs.",
    selector: '[href="/campaign/c2"]',
  },
  {
    title: "Review Findings",
    description: "View discovered vulnerabilities grouped by severity with proof-of-concept details.",
    selector: '[href="/campaign/vulns"]',
  },
  {
    title: "You're all set!",
    description: "Start your first campaign and let the framework do the heavy lifting.",
    selector: null,
  },
];

export default function OnboardingTour() {
  const hasSeenTour = useUIStore((s) => s.hasSeenTour);
  const setHasSeenTour = useUIStore((s) => s.setHasSeenTour);
  const [step, setStep] = useState(0);
  const [position, setPosition] = useState<{ top: number; left: number } | null>(null);
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    if (!hasSeenTour) {
      const timer = setTimeout(() => setVisible(true), 500);
      return () => clearTimeout(timer);
    }
  }, [hasSeenTour]);

  /* eslint-disable react-hooks/set-state-in-effect -- syncing external DOM measurements into state */
  useEffect(() => {
    const current = TOUR_STEPS[step];
    if (!current?.selector) {
      setPosition(null);
      return;
    }
    const el = document.querySelector(current.selector);
    if (el) {
      const rect = el.getBoundingClientRect();
      setPosition({
        top: rect.top + rect.height / 2,
        left: rect.right + 16,
      });
    }
  }, [step]);
  /* eslint-enable react-hooks/set-state-in-effect */

  const close = useCallback(() => {
    setVisible(false);
    setHasSeenTour(true);
  }, [setHasSeenTour]);

  const next = () => {
    if (step < TOUR_STEPS.length - 1) {
      setStep(step + 1);
    } else {
      close();
    }
  };

  const prev = () => {
    if (step > 0) setStep(step - 1);
  };

  if (hasSeenTour || !visible) return null;

  const current = TOUR_STEPS[step];
  const isFirst = step === 0;
  const isLast = step === TOUR_STEPS.length - 1;

  return (
    <>
      {/* Backdrop */}
      <div className="fixed inset-0 z-[100] bg-bg-void/80 backdrop-blur-sm" />

      {/* Tooltip */}
      <div
        className="fixed z-[101] w-80 rounded-lg border border-neon-orange/30 bg-bg-secondary p-4 shadow-lg shadow-neon-orange/5 animate-fade-in"
        style={
          position
            ? { top: `${position.top}px`, left: `${position.left}px`, transform: "translateY(-50%)" }
            : { top: "50%", left: "50%", transform: "translate(-50%, -50%)" }
        }
      >
        {/* Close button */}
        <button
          onClick={close}
          className="absolute right-2 top-2 text-text-muted hover:text-text-primary"
        >
          <X className="h-3.5 w-3.5" />
        </button>

        {/* Content */}
        {isFirst && (
          <div className="mb-3 flex items-center gap-2">
            <Shield className="h-5 w-5 text-neon-orange" />
          </div>
        )}
        <h3 className="text-sm font-bold text-text-primary">{current.title}</h3>
        <p className="mt-1 text-xs text-text-secondary">{current.description}</p>

        {/* Progress + Navigation */}
        <div className="mt-4 flex items-center justify-between">
          <div className="flex gap-1">
            {TOUR_STEPS.map((_, i) => (
              <span
                key={i}
                className={`h-1.5 w-1.5 rounded-full transition-colors ${
                  i === step ? "bg-neon-orange" : i < step ? "bg-neon-orange/40" : "bg-border"
                }`}
              />
            ))}
          </div>
          <div className="flex gap-2">
            {!isFirst && (
              <button
                onClick={prev}
                className="flex items-center gap-1 rounded px-2 py-1 text-xs text-text-muted hover:text-text-primary"
              >
                <ChevronLeft className="h-3 w-3" />
                Back
              </button>
            )}
            <button
              onClick={next}
              className="flex items-center gap-1 rounded bg-neon-orange/15 px-3 py-1 text-xs font-medium text-neon-orange hover:bg-neon-orange/25"
            >
              {isLast ? "Get Started" : "Next"}
              {!isLast && <ChevronRight className="h-3 w-3" />}
            </button>
          </div>
        </div>
      </div>
    </>
  );
}
