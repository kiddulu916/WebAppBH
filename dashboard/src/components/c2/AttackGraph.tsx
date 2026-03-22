"use client";

import { useEffect, useRef, useState } from "react";
import { Loader2, Network } from "lucide-react";
import { api } from "@/lib/api";
import { useCampaignStore } from "@/stores/campaign";

interface GraphNode {
  id: string;
  label: string;
  type: string;
  severity?: string;
  x?: number;
  y?: number;
  vx?: number;
  vy?: number;
}

interface GraphEdge {
  source: string;
  target: string;
}

const TYPE_COLORS: Record<string, string> = {
  target: "#3b82f6",
  domain: "#22c55e",
  subdomain: "#22c55e",
  ip: "#f59e0b",
  port: "#8b5cf6",
  vulnerability: "#ef4444",
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#dc2626",
  high: "#ef4444",
  medium: "#f59e0b",
  low: "#3b82f6",
  info: "#6b7280",
};

export default function AttackGraph() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const activeTarget = useCampaignStore((s) => s.activeTarget);
  const [nodes, setNodes] = useState<GraphNode[]>([]);
  const [edges, setEdges] = useState<GraphEdge[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!activeTarget) return;
    setLoading(true);
    api
      .getAttackGraph(activeTarget.id)
      .then((res) => {
        setNodes(res.nodes);
        setEdges(res.edges);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [activeTarget]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || nodes.length === 0) return;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const width = canvas.width;
    const height = canvas.height;

    // Simple force-directed layout
    const positioned = nodes.map((n, i) => ({
      ...n,
      x: width / 2 + (Math.cos((i / nodes.length) * Math.PI * 2) * Math.min(width, height)) / 3,
      y: height / 2 + (Math.sin((i / nodes.length) * Math.PI * 2) * Math.min(width, height)) / 3,
    }));

    const nodeMap = new Map(positioned.map((n) => [n.id, n]));

    // Run simple force iterations
    for (let iter = 0; iter < 100; iter++) {
      // Repulsion
      for (let i = 0; i < positioned.length; i++) {
        for (let j = i + 1; j < positioned.length; j++) {
          const a = positioned[i];
          const b = positioned[j];
          const dx = b.x! - a.x!;
          const dy = b.y! - a.y!;
          const dist = Math.max(Math.sqrt(dx * dx + dy * dy), 1);
          const force = 2000 / (dist * dist);
          a.x! -= (dx / dist) * force;
          a.y! -= (dy / dist) * force;
          b.x! += (dx / dist) * force;
          b.y! += (dy / dist) * force;
        }
      }
      // Attraction along edges
      for (const edge of edges) {
        const src = nodeMap.get(edge.source);
        const tgt = nodeMap.get(edge.target);
        if (!src || !tgt) continue;
        const dx = tgt.x! - src.x!;
        const dy = tgt.y! - src.y!;
        const dist = Math.max(Math.sqrt(dx * dx + dy * dy), 1);
        const force = (dist - 80) * 0.01;
        src.x! += (dx / dist) * force;
        src.y! += (dy / dist) * force;
        tgt.x! -= (dx / dist) * force;
        tgt.y! -= (dy / dist) * force;
      }
      // Center gravity
      for (const n of positioned) {
        n.x! += (width / 2 - n.x!) * 0.01;
        n.y! += (height / 2 - n.y!) * 0.01;
      }
    }

    // Draw
    ctx.clearRect(0, 0, width, height);

    // Edges
    ctx.strokeStyle = "#374151";
    ctx.lineWidth = 1;
    for (const edge of edges) {
      const src = nodeMap.get(edge.source);
      const tgt = nodeMap.get(edge.target);
      if (!src || !tgt) continue;
      ctx.beginPath();
      ctx.moveTo(src.x!, src.y!);
      ctx.lineTo(tgt.x!, tgt.y!);
      ctx.stroke();
    }

    // Nodes
    for (const n of positioned) {
      const color = n.severity
        ? SEVERITY_COLORS[n.severity] || "#6b7280"
        : TYPE_COLORS[n.type] || "#6b7280";
      const radius = n.type === "target" ? 10 : n.type === "vulnerability" ? 7 : 5;

      ctx.beginPath();
      ctx.arc(n.x!, n.y!, radius, 0, Math.PI * 2);
      ctx.fillStyle = color;
      ctx.fill();
      ctx.strokeStyle = "#1f2937";
      ctx.lineWidth = 1.5;
      ctx.stroke();

      // Label
      ctx.fillStyle = "#d1d5db";
      ctx.font = "10px monospace";
      ctx.textAlign = "center";
      const label = n.label.length > 20 ? n.label.slice(0, 20) + "..." : n.label;
      ctx.fillText(label, n.x!, n.y! + radius + 12);
    }
  }, [nodes, edges]);

  if (loading) {
    return (
      <div className="flex h-96 items-center justify-center">
        <Loader2 className="h-5 w-5 animate-spin text-accent" />
      </div>
    );
  }

  if (nodes.length === 0) {
    return (
      <div className="flex h-96 items-center justify-center rounded-lg border border-border bg-bg-secondary">
        <div className="text-center">
          <Network className="mx-auto h-8 w-8 text-text-muted" />
          <p className="mt-2 text-sm text-text-muted">No graph data available</p>
        </div>
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-border bg-bg-secondary p-2">
      <div className="mb-2 flex items-center gap-2">
        <Network className="h-4 w-4 text-accent" />
        <span className="text-sm font-semibold text-text-primary">Attack Surface Graph</span>
        <span className="text-xs text-text-muted">
          {nodes.length} nodes · {edges.length} edges
        </span>
      </div>
      <canvas
        ref={canvasRef}
        width={800}
        height={500}
        className="w-full rounded bg-bg-primary"
      />
      <div className="mt-2 flex flex-wrap gap-3 text-[10px]">
        {Object.entries(TYPE_COLORS).map(([type, color]) => (
          <div key={type} className="flex items-center gap-1">
            <div className="h-2 w-2 rounded-full" style={{ backgroundColor: color }} />
            <span className="text-text-muted">{type}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
