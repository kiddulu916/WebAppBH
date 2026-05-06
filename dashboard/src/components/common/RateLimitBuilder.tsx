"use client";

import { Plus, Trash2 } from "lucide-react";

export interface RateLimitRule {
  amount: number;
  unit: string;
}

const UNIT_OPTIONS = [
  { value: "req/s", label: "req/s" },
  { value: "req/min", label: "req/min" },
  { value: "req/hr", label: "req/hr" },
  { value: "req/day", label: "req/day" },
  { value: "KB/s", label: "KB/s" },
  { value: "MB/s", label: "MB/s" },
];

interface Props {
  rules: RateLimitRule[];
  onChange: (rules: RateLimitRule[]) => void;
  label?: string;
}

export default function RateLimitBuilder({
  rules,
  onChange,
  label = "Rate Limits",
}: Props) {
  function addRule() {
    onChange([...rules, { amount: 50, unit: "req/s" }]);
  }

  function removeRule(index: number) {
    onChange(rules.filter((_, i) => i !== index));
  }

  function updateRule(index: number, field: keyof RateLimitRule, value: string | number) {
    const updated = rules.map((r, i) =>
      i === index ? { ...r, [field]: value } : r,
    );
    onChange(updated);
  }

  return (
    <div className="space-y-2">
      <label className="section-label block">{label}</label>

      {rules.map((rule, i) => (
        <div key={i} className="flex items-center gap-2">
          <input
            type="number"
            min={1}
            value={rule.amount}
            onChange={(e) => updateRule(i, "amount", parseInt(e.target.value) || 1)}
            className="w-24 rounded border border-border bg-bg-tertiary px-2 py-1.5 text-xs font-mono text-text-primary focus:border-accent focus:outline-none"
          />
          <select
            value={rule.unit}
            onChange={(e) => updateRule(i, "unit", e.target.value)}
            className="rounded border border-border bg-bg-tertiary px-2 py-1.5 text-xs text-text-primary focus:border-accent focus:outline-none"
          >
            {UNIT_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
          {rules.length > 1 && (
            <button
              type="button"
              onClick={() => removeRule(i)}
              className="text-text-muted hover:text-red-400"
            >
              <Trash2 className="h-3.5 w-3.5" />
            </button>
          )}
        </div>
      ))}

      <button
        type="button"
        onClick={addRule}
        className="flex items-center gap-1 text-xs text-accent hover:underline"
      >
        <Plus className="h-3 w-3" /> Add rule
      </button>
    </div>
  );
}
