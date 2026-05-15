"use client";

import { Plus, Trash2 } from "lucide-react";

export interface CustomHeader {
  key: string;
  value: string;
}

interface Props {
  headers: CustomHeader[];
  onChange: (headers: CustomHeader[]) => void;
  label?: string;
}

export default function CustomHeaderBuilder({
  headers,
  onChange,
  label = "Custom Request Headers",
}: Props) {
  function addHeader() {
    onChange([...headers, { key: "", value: "" }]);
  }

  function removeHeader(index: number) {
    onChange(headers.filter((_, i) => i !== index));
  }

  function updateHeader(index: number, field: keyof CustomHeader, value: string) {
    const updated = headers.map((h, i) =>
      i === index ? { ...h, [field]: value } : h,
    );
    onChange(updated);
  }

  return (
    <div className="space-y-2">
      <label className="section-label block">{label}</label>

      {headers.map((header, i) => (
        <div key={i} className="flex items-center gap-2">
          <input
            data-testid={`header-key-${i}`}
            type="text"
            value={header.key}
            onChange={(e) => updateHeader(i, "key", e.target.value)}
            placeholder="Header-Name"
            className="w-36 rounded border border-border bg-bg-tertiary px-2 py-1.5 text-xs font-mono text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none"
          />
          <span className="text-xs text-text-muted">:</span>
          <input
            data-testid={`header-value-${i}`}
            type="text"
            value={header.value}
            onChange={(e) => updateHeader(i, "value", e.target.value)}
            placeholder="value"
            className="flex-1 rounded border border-border bg-bg-tertiary px-2 py-1.5 text-xs font-mono text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none"
          />
          <button
            type="button"
            data-testid={`header-remove-${i}`}
            onClick={() => removeHeader(i)}
            className="text-text-muted hover:text-red-400"
          >
            <Trash2 className="h-3.5 w-3.5" />
          </button>
        </div>
      ))}

      <button
        data-testid="header-add-btn"
        type="button"
        onClick={addHeader}
        className="flex items-center gap-1 text-xs text-accent hover:underline"
      >
        <Plus className="h-3 w-3" /> Add header
      </button>
    </div>
  );
}
