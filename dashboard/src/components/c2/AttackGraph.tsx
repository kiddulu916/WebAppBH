"use client";

import { useEffect, useRef, useState, useCallback, useMemo } from "react";
import { Loader2, Network, ZoomIn, ZoomOut, RotateCcw } from "lucide-react";
import { api } from "@/lib/api";
import { useCampaignStore } from "@/stores/campaign";

interface GraphNode {
  id: string;
  label: string;
  type: string;
  severity?: string;
  x?: number;
  y?: number;
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

const NODE_TYPES = ["target", "domain", "subdomain", "ip", "port", "vulnerability"];

export default function AttackGraph() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const activeTarget = useCampaignStore((s) => s.activeTarget);
  const [nodes, setNodes] = useState<GraphNode[]>([]);
  const [edges, setEdges] = useState<GraphEdge[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [visibleTypes, setVisibleTypes] = useState<Set<string>>(new Set(NODE_TYPES));
  const [scale, setScale] = useState(1);
  const [offset, setOffset] = useState({ x: 0, y: 0 });
  const [dragging, setDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const positionedRef = useRef<GraphNode[]>([]);

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

  // Run layout once when nodes change
  useEffect(() => {
    if (nodes.length === 0) return;
    const width = 800;
    const height = 500;

    const positioned = nodes.map((n, i) => ({
      ...n,
      x: width / 2 + (Math.cos((i / nodes.length) * Math.PI * 2) * Math.min(width, height)) / 3,
      y: height / 2 + (Math.sin((i / nodes.length) * Math.PI * 2) * Math.min(width, height)) / 3,
    }));

    const nodeMap = new Map(positioned.map((n) => [n.id, n]));

    for (let iter = 0; iter < 100; iter++) {
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
      for (const n of positioned) {
        n.x! += (width / 2 - n.x!) * 0.01;
        n.y! += (height / 2 - n.y!) * 0.01;
      }
    }

    positionedRef.current = positioned;
  }, [nodes, edges]);

  // Filtered nodes and edges
  const { filteredNodes, filteredEdges } = useMemo(() => {
    const fn = positionedRef.current.filter((n) => visibleTypes.has(n.type));
    const fnIds = new Set(fn.map((n) => n.id));
    const fe = edges.filter((e) => fnIds.has(e.source) && fnIds.has(e.target));
    return { filteredNodes: fn, filteredEdges: fe };
  }, [edges, visibleTypes, nodes]); // nodes dep ensures recalc after layout

  // Draw
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || filteredNodes.length === 0) return;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const width = canvas.width;
    const height = canvas.height;
    const nodeMap = new Map(filteredNodes.map((n) => [n.id, n]));

    ctx.clearRect(0, 0, width, height);
    ctx.save();
    ctx.translate(offset.x, offset.y);
    ctx.scale(scale, scale);

    // Edges
    ctx.strokeStyle = "#374151";
    ctx.lineWidth = 1 / scale;
    for (const edge of filteredEdges) {
      const src = nodeMap.get(edge.source);
      const tgt = nodeMap.get(edge.target);
      if (!src || !tgt) continue;
      ctx.beginPath();
      ctx.moveTo(src.x!, src.y!);
      ctx.lineTo(tgt.x!, tgt.y!);
      ctx.stroke();
    }

    // Nodes
    for (const n of filteredNodes) {
      const color = n.severity
        ? SEVERITY_COLORS[n.severity] || "#6b7280"
        : TYPE_COLORS[n.type] || "#6b7280";
      const radius = n.type === "target" ? 10 : n.type === "vulnerability" ? 7 : 5;
      const isSelected = selectedNode?.id === n.id;

      ctx.beginPath();
      ctx.arc(n.x!, n.y!, isSelected ? radius + 3 : radius, 0, Math.PI * 2);
      ctx.fillStyle = color;
      ctx.fill();

      if (isSelected) {
        ctx.strokeStyle = "#ffffff";
        ctx.lineWidth = 2 / scale;
      } else {
        ctx.strokeStyle = "#1f2937";
        ctx.lineWidth = 1.5 / scale;
      }
      ctx.stroke();

      // Label
      ctx.fillStyle = "#d1d5db";
      ctx.font = `${10 / scale}px monospace`;
      ctx.textAlign = "center";
      const label = n.label.length > 20 ? n.label.slice(0, 20) + "..." : n.label;
      ctx.fillText(label, n.x!, n.y! + radius + 12 / scale);
    }

    ctx.restore();
  }, [filteredNodes, filteredEdges, scale, offset, selectedNode]);

  // Handlers
  const handleWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault();
    const factor = e.deltaY > 0 ? 0.9 : 1.1;
    setScale((s) => Math.min(Math.max(s * factor, 0.2), 5));
  }, []);

  const handleMouseDown = useCallback(
    (e: React.MouseEvent) => {
      setDragging(true);
      setDragStart({ x: e.clientX - offset.x, y: e.clientY - offset.y });
    },
    [offset],
  );

  const handleMouseMove = useCallback(
    (e: React.MouseEvent) => {
      if (!dragging) return;
      setOffset({ x: e.clientX - dragStart.x, y: e.clientY - dragStart.y });
    },
    [dragging, dragStart],
  );

  const handleMouseUp = useCallback(() => {
    setDragging(false);
  }, []);

  const handleClick = useCallback(
    (e: React.MouseEvent) => {
      const canvas = canvasRef.current;
      if (!canvas) return;
      const rect = canvas.getBoundingClientRect();
      const mx = (e.clientX - rect.left - offset.x) / scale;
      const my = (e.clientY - rect.top - offset.y) / scale;

      let closest: GraphNode | null = null;
      let closestDist = Infinity;
      for (const n of filteredNodes) {
        const dx = n.x! - mx;
        const dy = n.y! - my;
        const dist = Math.sqrt(dx * dx + dy * dy);
        const radius = n.type === "target" ? 10 : n.type === "vulnerability" ? 7 : 5;
        if (dist < radius + 5 && dist < closestDist) {
          closest = n;
          closestDist = dist;
        }
      }
      setSelectedNode(closest);
    },
    [filteredNodes, offset, scale],
  );

  const toggleType = (type: string) => {
    setVisibleTypes((prev) => {
      const next = new Set(prev);
      if (next.has(type)) next.delete(type);
      else next.add(type);
      return next;
    });
  };

  const resetView = () => {
    setScale(1);
    setOffset({ x: 0, y: 0 });
    setSelectedNode(null);
  };

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
      {/* Header + controls */}
      <div className="mb-2 flex items-center gap-2 flex-wrap">
        <Network className="h-4 w-4 text-accent" />
        <span className="text-sm font-semibold text-text-primary">Attack Surface Graph</span>
        <span className="text-xs text-text-muted">
          {filteredNodes.length} nodes · {filteredEdges.length} edges
        </span>
        <div className="ml-auto flex items-center gap-1">
          <button
            onClick={() => setScale((s) => Math.min(s * 1.2, 5))}
            className="rounded p-1 text-text-muted hover:bg-bg-surface hover:text-text-primary"
            title="Zoom In"
          >
            <ZoomIn className="h-3.5 w-3.5" />
          </button>
          <button
            onClick={() => setScale((s) => Math.max(s * 0.8, 0.2))}
            className="rounded p-1 text-text-muted hover:bg-bg-surface hover:text-text-primary"
            title="Zoom Out"
          >
            <ZoomOut className="h-3.5 w-3.5" />
          </button>
          <button
            onClick={resetView}
            className="rounded p-1 text-text-muted hover:bg-bg-surface hover:text-text-primary"
            title="Reset View"
          >
            <RotateCcw className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      {/* Type filters */}
      <div className="mb-2 flex flex-wrap gap-2">
        {NODE_TYPES.map((type) => {
          const active = visibleTypes.has(type);
          const color = TYPE_COLORS[type] || "#6b7280";
          return (
            <label key={type} className="flex items-center gap-1.5 cursor-pointer">
              <input
                type="checkbox"
                checked={active}
                onChange={() => toggleType(type)}
                className="accent-neon-orange h-3 w-3"
              />
              <span className="flex items-center gap-1 text-[10px] text-text-muted">
                <span className="h-2 w-2 rounded-full" style={{ backgroundColor: color }} />
                {type}
              </span>
            </label>
          );
        })}
      </div>

      {/* Canvas */}
      <canvas
        ref={canvasRef}
        width={800}
        height={500}
        className="w-full rounded bg-bg-primary cursor-grab active:cursor-grabbing"
        onWheel={handleWheel}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
        onClick={handleClick}
      />

      {/* Selected node detail */}
      {selectedNode && (
        <div className="mt-2 rounded-md border border-border bg-bg-tertiary p-3 animate-fade-in">
          <div className="flex items-center gap-2">
            <span
              className="h-3 w-3 rounded-full"
              style={{
                backgroundColor: selectedNode.severity
                  ? SEVERITY_COLORS[selectedNode.severity] || "#6b7280"
                  : TYPE_COLORS[selectedNode.type] || "#6b7280",
              }}
            />
            <span className="font-mono text-sm text-text-primary">{selectedNode.label}</span>
            <span className="rounded bg-bg-surface px-1.5 py-0.5 text-[10px] text-text-muted">
              {selectedNode.type}
            </span>
            {selectedNode.severity && (
              <span className="rounded bg-bg-surface px-1.5 py-0.5 text-[10px] font-mono text-text-muted">
                {selectedNode.severity.toUpperCase()}
              </span>
            )}
          </div>
        </div>
      )}

      {/* Legend */}
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
