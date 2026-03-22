"use client";

import AttackGraph from "@/components/c2/AttackGraph";

export default function GraphPage() {
  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-bold text-text-primary">Attack Graph</h1>
        <p className="mt-1 text-sm text-text-secondary">
          Visual map of discovered attack surface: targets, assets, ports, and vulnerabilities
        </p>
      </div>
      <AttackGraph />
    </div>
  );
}
