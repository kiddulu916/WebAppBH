"use client";

import { useEffect, useState, useCallback, useMemo, useRef } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  Handle,
  Position,
  useNodesState,
  useEdgesState,
  useReactFlow,
  ReactFlowProvider,
  type Node,
  type Edge,
  type NodeMouseHandler,
  type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
  Network,
  Loader2,
  X,
  RotateCcw,
  Maximize2,
  Shield,
  AlertTriangle,
  RefreshCw,
} from "lucide-react";
import { api } from "@/lib/api";
import { useCampaignStore } from "@/stores/campaign";
import type { AttackPath } from "@/types/schema";

/* ------------------------------------------------------------------ */
/* Types                                                               */
/* ------------------------------------------------------------------ */

interface ApiGraphNode {
  id: string;
  label: string;
  type: string;
  severity?: string;
}

interface ApiGraphEdge {
  source: string;
  target: string;
}

interface NodeData extends Record<string, unknown> {
  label: string;
  nodeType: string;
  nodeId: string;
  severity?: string;
  connectedCount: number;
  ports?: number;
  vulnCount?: number;
  description?: string;
  title?: string;
}

/* ------------------------------------------------------------------ */
/* Layout Types                                                        */
/* ------------------------------------------------------------------ */

type LayoutType = "hierarchical" | "force-directed" | "radial";

/* ------------------------------------------------------------------ */
/* Custom graph node (renders data-testid on each node wrapper)        */
/* ------------------------------------------------------------------ */

type GraphNodeType = Node<NodeData, "graphNode">;

function GraphNodeComponent({ data }: NodeProps<GraphNodeType>) {
  return (
    <div data-testid={`graph-node-${data.nodeId}`}>
      <Handle type="target" position={Position.Top} style={{ visibility: "hidden" }} />
      <div>{data.label}</div>
      <Handle type="source" position={Position.Bottom} style={{ visibility: "hidden" }} />
    </div>
  );
}

const nodeTypes = { graphNode: GraphNodeComponent };

/* ------------------------------------------------------------------ */
/* Node styling                                                        */
/* ------------------------------------------------------------------ */

function getNodeStyle(type: string, severity?: string): React.CSSProperties {
  const base: React.CSSProperties = {
    borderRadius: 8,
    fontSize: 12,
    padding: "8px 12px",
  };
  switch (type) {
    case "target":
      return { ...base, background: "#064e3b", border: "2px solid #10b981", color: "#6ee7b7" };
    case "subdomain":
      return { ...base, background: "#1e3a5f", border: "2px solid #3b82f6", color: "#93c5fd" };
    case "ip":
      return { ...base, background: "#4a2c17", border: "2px solid #f97316", color: "#fdba74" };
    case "cidr":
      return { ...base, background: "#064e3b", border: "2px solid #10b981", color: "#6ee7b7" };
    case "port":
      return { ...base, background: "#1f1f1f", border: "1px solid #525252", color: "#a3a3a3" };
    case "vulnerability": {
      const colors: Record<string, { bg: string; border: string; text: string }> = {
        critical: { bg: "#4c1d1d", border: "#ef4444", text: "#fca5a5" },
        high: { bg: "#4a2c17", border: "#f97316", text: "#fdba74" },
        medium: { bg: "#422006", border: "#eab308", text: "#fde047" },
        low: { bg: "#1e3a5f", border: "#3b82f6", text: "#93c5fd" },
        info: { bg: "#1f1f1f", border: "#525252", text: "#a3a3a3" },
      };
      const c = colors[severity || "info"] || colors.info;
      return { ...base, background: c.bg, border: `2px solid ${c.border}`, color: c.text };
    }
    default:
      return base;
  }
}

/* ------------------------------------------------------------------ */
/* Layout algorithms                                                   */
/* ------------------------------------------------------------------ */

function layoutHierarchical(apiNodes: ApiGraphNode[], apiEdges: ApiGraphEdge[]): Node<NodeData>[] {
  const typeY: Record<string, number> = {
    target: 0,
    subdomain: 150,
    ip: 150,
    cidr: 150,
    port: 300,
    vulnerability: 450,
  };

  // Group nodes by layer for better horizontal distribution
  const layers: Record<number, ApiGraphNode[]> = {};
  for (const n of apiNodes) {
    const y = typeY[n.type] ?? 200;
    if (!layers[y]) layers[y] = [];
    layers[y].push(n);
  }

  const connMap = buildConnectionMap(apiNodes, apiEdges);

  const result: Node<NodeData>[] = [];
  for (const [yStr, layerNodes] of Object.entries(layers)) {
    const y = Number(yStr);
    const spacing = 220;
    const startX = -(layerNodes.length - 1) * spacing / 2;
    for (let i = 0; i < layerNodes.length; i++) {
      const n = layerNodes[i];
      result.push({
        id: n.id,
        type: "graphNode",
        position: { x: startX + i * spacing + (Math.random() * 40 - 20), y },
        data: {
          label: n.label,
          nodeType: n.type,
          nodeId: n.id,
          severity: n.severity,
          connectedCount: connMap.get(n.id) ?? 0,
        },
        style: getNodeStyle(n.type, n.severity),
      });
    }
  }

  return result;
}

function layoutForceDirected(apiNodes: ApiGraphNode[], apiEdges: ApiGraphEdge[]): Node<NodeData>[] {
  const connMap = buildConnectionMap(apiNodes, apiEdges);

  // Initial circle layout
  const positions = apiNodes.map((_, i) => ({
    x: 400 + Math.cos((i / apiNodes.length) * Math.PI * 2) * 250,
    y: 300 + Math.sin((i / apiNodes.length) * Math.PI * 2) * 250,
  }));

  const nodeIdx = new Map(apiNodes.map((n, i) => [n.id, i]));

  // Simple force-directed iterations
  for (let iter = 0; iter < 80; iter++) {
    // Repulsion
    for (let i = 0; i < positions.length; i++) {
      for (let j = i + 1; j < positions.length; j++) {
        const dx = positions[j].x - positions[i].x;
        const dy = positions[j].y - positions[i].y;
        const dist = Math.max(Math.sqrt(dx * dx + dy * dy), 1);
        const force = 3000 / (dist * dist);
        positions[i].x -= (dx / dist) * force;
        positions[i].y -= (dy / dist) * force;
        positions[j].x += (dx / dist) * force;
        positions[j].y += (dy / dist) * force;
      }
    }
    // Attraction along edges
    for (const edge of apiEdges) {
      const si = nodeIdx.get(edge.source);
      const ti = nodeIdx.get(edge.target);
      if (si === undefined || ti === undefined) continue;
      const dx = positions[ti].x - positions[si].x;
      const dy = positions[ti].y - positions[si].y;
      const dist = Math.max(Math.sqrt(dx * dx + dy * dy), 1);
      const force = (dist - 100) * 0.008;
      positions[si].x += (dx / dist) * force;
      positions[si].y += (dy / dist) * force;
      positions[ti].x -= (dx / dist) * force;
      positions[ti].y -= (dy / dist) * force;
    }
    // Center gravity
    for (const p of positions) {
      p.x += (400 - p.x) * 0.01;
      p.y += (300 - p.y) * 0.01;
    }
  }

  return apiNodes.map((n, i) => ({
    id: n.id,
    type: "graphNode",
    position: { x: positions[i].x, y: positions[i].y },
    data: {
      label: n.label,
      nodeType: n.type,
      nodeId: n.id,
      severity: n.severity,
      connectedCount: connMap.get(n.id) ?? 0,
    },
    style: getNodeStyle(n.type, n.severity),
  }));
}

function layoutRadial(apiNodes: ApiGraphNode[], apiEdges: ApiGraphEdge[]): Node<NodeData>[] {
  const connMap = buildConnectionMap(apiNodes, apiEdges);

  const typeRing: Record<string, number> = {
    target: 0,
    subdomain: 1,
    ip: 1,
    cidr: 1,
    port: 2,
    vulnerability: 3,
  };

  const rings: Record<number, ApiGraphNode[]> = {};
  for (const n of apiNodes) {
    const ring = typeRing[n.type] ?? 2;
    if (!rings[ring]) rings[ring] = [];
    rings[ring].push(n);
  }

  const cx = 400;
  const cy = 350;
  const ringSpacing = 160;

  const result: Node<NodeData>[] = [];
  for (const [ringStr, ringNodes] of Object.entries(rings)) {
    const ring = Number(ringStr);
    const radius = ring * ringSpacing;
    for (let i = 0; i < ringNodes.length; i++) {
      const n = ringNodes[i];
      const angle = (i / ringNodes.length) * Math.PI * 2 - Math.PI / 2;
      result.push({
        id: n.id,
        type: "graphNode",
        position: {
          x: cx + (radius === 0 ? 0 : Math.cos(angle) * radius),
          y: cy + (radius === 0 ? 0 : Math.sin(angle) * radius),
        },
        data: {
          label: n.label,
          nodeType: n.type,
          nodeId: n.id,
          severity: n.severity,
          connectedCount: connMap.get(n.id) ?? 0,
        },
        style: getNodeStyle(n.type, n.severity),
      });
    }
  }

  return result;
}

function buildConnectionMap(apiNodes: ApiGraphNode[], apiEdges: ApiGraphEdge[]): Map<string, number> {
  const map = new Map<string, number>();
  for (const n of apiNodes) map.set(n.id, 0);
  for (const e of apiEdges) {
    map.set(e.source, (map.get(e.source) ?? 0) + 1);
    map.set(e.target, (map.get(e.target) ?? 0) + 1);
  }
  return map;
}

function applyLayout(
  layout: LayoutType,
  apiNodes: ApiGraphNode[],
  apiEdges: ApiGraphEdge[],
): Node<NodeData>[] {
  switch (layout) {
    case "hierarchical":
      return layoutHierarchical(apiNodes, apiEdges);
    case "force-directed":
      return layoutForceDirected(apiNodes, apiEdges);
    case "radial":
      return layoutRadial(apiNodes, apiEdges);
    default:
      return layoutHierarchical(apiNodes, apiEdges);
  }
}

function toFlowEdges(apiEdges: ApiGraphEdge[]): Edge[] {
  return apiEdges.map((e) => ({
    id: `${e.source}-${e.target}`,
    source: e.source,
    target: e.target,
    style: { stroke: "#525252", strokeWidth: 1.5 },
    animated: false,
  }));
}

/* ------------------------------------------------------------------ */
/* Severity helpers                                                    */
/* ------------------------------------------------------------------ */

const SEVERITY_ORDER: Record<string, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
  info: "#6b7280",
};

/* ------------------------------------------------------------------ */
/* Inner graph component (must be inside ReactFlowProvider)             */
/* ------------------------------------------------------------------ */

function AttackGraphInner() {
  const activeTarget = useCampaignStore((s) => s.activeTarget);
  const { fitView } = useReactFlow();

  /* Raw API data */
  const [apiNodes, setApiNodes] = useState<ApiGraphNode[]>([]);
  const [apiEdges, setApiEdges] = useState<ApiGraphEdge[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  /* Attack paths */
  const [attackPaths, setAttackPaths] = useState<AttackPath[]>([]);
  const [showPaths, setShowPaths] = useState(false);
  const [selectedPathId, setSelectedPathId] = useState<number | null>(null);

  /* Controls */
  const [layoutType, setLayoutType] = useState<LayoutType>("hierarchical");
  const [filterTypes, setFilterTypes] = useState({
    subdomain: true,
    ip: true,
    cloud: true,
  });
  const [minSeverity, setMinSeverity] = useState(0);

  /* Detail sidebar */
  const [selectedNode, setSelectedNode] = useState<NodeData | null>(null);
  const [sidebarOpen, setSidebarOpen] = useState(false);

  /* React Flow state */
  const [nodes, setNodes, onNodesChange] = useNodesState<Node<NodeData>>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);

  /* Store raw data ref for layout recalc */
  const rawRef = useRef<{ nodes: ApiGraphNode[]; edges: ApiGraphEdge[] }>({
    nodes: [],
    edges: [],
  });

  /* ---------------------------------------------------------------- */
  /* Fetch graph data                                                  */
  /* ---------------------------------------------------------------- */

  useEffect(() => {
    if (!activeTarget) {
      setApiNodes([]);
      setApiEdges([]);
      setLoading(false);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError(null);

    api
      .getAttackGraph(activeTarget.id)
      .then((res) => {
        if (cancelled) return;
        setApiNodes(res.nodes);
        setApiEdges(res.edges);
        rawRef.current = { nodes: res.nodes, edges: res.edges };
      })
      .catch((err) => {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : "Failed to load graph");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [activeTarget]);

  /* Fetch attack paths */
  useEffect(() => {
    if (!activeTarget) return;
    let cancelled = false;

    api
      .getAttackPaths(activeTarget.id)
      .then((res) => {
        if (!cancelled) setAttackPaths(res.paths ?? []);
      })
      .catch(() => {
        /* silently ignore */
      });

    return () => {
      cancelled = true;
    };
  }, [activeTarget]);

  /* ---------------------------------------------------------------- */
  /* Apply filters and layout                                          */
  /* ---------------------------------------------------------------- */

  const filteredApiData = useMemo(() => {
    let filteredNodes = apiNodes;

    // Filter by type
    filteredNodes = filteredNodes.filter((n) => {
      if (n.type === "subdomain" && !filterTypes.subdomain) return false;
      if (n.type === "ip" && !filterTypes.ip) return false;
      if ((n.type === "cidr" || n.type === "cloud") && !filterTypes.cloud) return false;
      return true;
    });

    // Filter by severity
    if (minSeverity > 0) {
      filteredNodes = filteredNodes.filter((n) => {
        if (n.type !== "vulnerability") return true;
        return (SEVERITY_ORDER[n.severity || "info"] || 0) >= minSeverity;
      });
    }

    const nodeIds = new Set(filteredNodes.map((n) => n.id));
    const filteredEdges = apiEdges.filter(
      (e) => nodeIds.has(e.source) && nodeIds.has(e.target),
    );

    return { nodes: filteredNodes, edges: filteredEdges };
  }, [apiNodes, apiEdges, filterTypes, minSeverity]);

  /* Apply layout when filtered data or layout type changes */
  useEffect(() => {
    if (filteredApiData.nodes.length === 0) {
      setNodes([]);
      setEdges([]);
      return;
    }

    const layoutNodes = applyLayout(layoutType, filteredApiData.nodes, filteredApiData.edges);
    let flowEdges = toFlowEdges(filteredApiData.edges);

    // Apply attack path highlighting
    if (showPaths && selectedPathId !== null) {
      const path = attackPaths.find((p) => p.id === selectedPathId);
      if (path) {
        const pathNodeIds = new Set(path.steps.map((s) => String(s.vuln_id)));
        const pathAssetIds = new Set(
          path.steps.filter((s) => s.asset_id).map((s) => String(s.asset_id)),
        );
        const highlightIds = new Set([...pathNodeIds, ...pathAssetIds]);

        flowEdges = flowEdges.map((e) => {
          const onPath =
            highlightIds.has(e.source) || highlightIds.has(e.target);
          return {
            ...e,
            style: onPath
              ? { stroke: "#ef4444", strokeWidth: 3 }
              : { stroke: "#525252", strokeWidth: 1, opacity: 0.3 },
            animated: onPath,
          };
        });
      }
    }

    setNodes(layoutNodes);
    setEdges(flowEdges);

    // Fit view after layout applies
    requestAnimationFrame(() => {
      fitView({ padding: 0.15 });
    });
  }, [filteredApiData, layoutType, showPaths, selectedPathId, attackPaths, setNodes, setEdges, fitView]);

  /* ---------------------------------------------------------------- */
  /* Handlers                                                          */
  /* ---------------------------------------------------------------- */

  const handleNodeClick: NodeMouseHandler = useCallback(
    (_event, node) => {
      const data = node.data as NodeData;
      setSelectedNode(data);
      setSidebarOpen(true);
    },
    [],
  );

  const handleFitView = useCallback(() => {
    fitView({ padding: 0.15 });
  }, [fitView]);

  const handleReset = useCallback(() => {
    if (rawRef.current.nodes.length === 0) return;
    setLayoutType("hierarchical");
    setFilterTypes({ subdomain: true, ip: true, cloud: true });
    setMinSeverity(0);
    setShowPaths(false);
    setSelectedPathId(null);
    setSelectedNode(null);
    setSidebarOpen(false);
  }, []);

  const handleRetry = useCallback(() => {
    if (!activeTarget) return;
    setLoading(true);
    setError(null);
    api
      .getAttackGraph(activeTarget.id)
      .then((res) => {
        setApiNodes(res.nodes);
        setApiEdges(res.edges);
        rawRef.current = { nodes: res.nodes, edges: res.edges };
      })
      .catch((err) => {
        setError(err instanceof Error ? err.message : "Failed to load graph");
      })
      .finally(() => setLoading(false));
  }, [activeTarget]);

  const handlePathClick = useCallback((pathId: number) => {
    setSelectedPathId((prev) => (prev === pathId ? null : pathId));
  }, []);

  const toggleFilterType = useCallback((type: "subdomain" | "ip" | "cloud") => {
    setFilterTypes((prev) => ({ ...prev, [type]: !prev[type] }));
  }, []);

  /* ---------------------------------------------------------------- */
  /* Severity slider label                                             */
  /* ---------------------------------------------------------------- */

  const severityLabel = useMemo(() => {
    const labels = ["All", "Info+", "Low+", "Medium+", "High+", "Critical"];
    return labels[minSeverity] ?? "All";
  }, [minSeverity]);

  /* ---------------------------------------------------------------- */
  /* Render: Loading                                                   */
  /* ---------------------------------------------------------------- */

  if (loading) {
    return (
      <div className="flex h-[calc(100vh-6rem)] w-full items-center justify-center">
        <Loader2 className="h-6 w-6 animate-spin text-accent" />
      </div>
    );
  }

  /* ---------------------------------------------------------------- */
  /* Render: Error overlay                                             */
  /* ---------------------------------------------------------------- */

  if (error) {
    return (
      <div
        data-testid="graph-error-overlay"
        className="flex h-[calc(100vh-6rem)] w-full items-center justify-center"
      >
        <div className="rounded-lg border border-danger/30 bg-danger/10 p-6 text-center">
          <AlertTriangle className="mx-auto mb-3 h-8 w-8 text-danger" />
          <p className="mb-4 text-sm text-danger">{error}</p>
          <button
            onClick={handleRetry}
            className="inline-flex items-center gap-2 rounded-md border border-border bg-bg-tertiary px-4 py-2 text-xs text-text-primary hover:bg-bg-surface"
          >
            <RefreshCw className="h-3.5 w-3.5" />
            Retry
          </button>
        </div>
      </div>
    );
  }

  /* ---------------------------------------------------------------- */
  /* Render: Empty state                                               */
  /* ---------------------------------------------------------------- */

  if (apiNodes.length === 0) {
    return (
      <div
        data-testid="graph-empty-state"
        className="flex h-[calc(100vh-6rem)] w-full items-center justify-center"
      >
        <div className="text-center">
          <Network className="mx-auto mb-3 h-10 w-10 text-text-muted" />
          <p className="text-sm text-text-muted">
            No assets to graph. Run a scan to populate the attack surface.
          </p>
        </div>
      </div>
    );
  }

  /* ---------------------------------------------------------------- */
  /* Render: Main graph                                                */
  /* ---------------------------------------------------------------- */

  return (
    <div className="h-[calc(100vh-6rem)] w-full relative" data-testid="graph-canvas">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={handleNodeClick}
        fitView
        proOptions={{ hideAttribution: true }}
      >
        <Background />
        <Controls />
        <MiniMap
          nodeStrokeWidth={3}
          style={{ background: "#0a0a0a" }}
        />
      </ReactFlow>

      {/* -------------------------------------------------------------- */}
      {/* Floating Control Panel — top-right                              */}
      {/* -------------------------------------------------------------- */}
      <div className="absolute top-4 right-4 z-10 w-64 rounded-lg border border-border bg-bg-secondary p-4 shadow-lg space-y-3">
        {/* Target label */}
        <div data-testid="graph-target-select" className="text-xs text-text-muted">
          <span className="text-text-secondary">Target: </span>
          <span className="font-mono text-text-primary">
            {activeTarget?.base_domain ?? "None"}
          </span>
        </div>

        {/* Attack paths toggle */}
        <div className="flex items-center justify-between">
          <span className="text-xs text-text-secondary">Attack Paths</span>
          <button
            data-testid="graph-attack-paths-toggle"
            onClick={() => {
              setShowPaths(!showPaths);
              if (showPaths) setSelectedPathId(null);
            }}
            className={`relative h-5 w-9 shrink-0 rounded-full transition-colors ${
              showPaths ? "bg-neon-green" : "bg-border-accent"
            }`}
          >
            <span
              className={`absolute top-0.5 left-0.5 h-4 w-4 rounded-full bg-white transition-transform ${
                showPaths ? "translate-x-4" : ""
              }`}
            />
          </button>
        </div>

        {/* Type filters */}
        <div className="space-y-1">
          <span className="text-[10px] uppercase tracking-wider text-text-muted">
            Filter by Type
          </span>
          {(["subdomain", "ip", "cloud"] as const).map((type) => (
            <label
              key={type}
              className="flex items-center gap-2 cursor-pointer"
            >
              <input
                data-testid={`graph-filter-type-${type}`}
                type="checkbox"
                checked={filterTypes[type]}
                onChange={() => toggleFilterType(type)}
                className="accent-neon-orange h-3 w-3"
              />
              <span className="text-xs text-text-secondary capitalize">{type}</span>
            </label>
          ))}
        </div>

        {/* Severity slider */}
        <div className="space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-[10px] uppercase tracking-wider text-text-muted">
              Min Severity
            </span>
            <span className="text-[10px] font-mono text-text-secondary">{severityLabel}</span>
          </div>
          <input
            data-testid="graph-severity-slider"
            type="range"
            min={0}
            max={5}
            step={1}
            value={minSeverity}
            onChange={(e) => setMinSeverity(Number(e.target.value))}
            className="w-full accent-neon-orange"
          />
        </div>

        {/* Layout select */}
        <div className="space-y-1">
          <span className="text-[10px] uppercase tracking-wider text-text-muted">Layout</span>
          <select
            data-testid="graph-layout-select"
            value={layoutType}
            onChange={(e) => setLayoutType(e.target.value as LayoutType)}
            className="w-full rounded-md border border-border bg-bg-tertiary px-2 py-1 text-xs text-text-primary"
          >
            <option value="hierarchical">Hierarchical</option>
            <option value="force-directed">Force-Directed</option>
            <option value="radial">Radial</option>
          </select>
        </div>

        {/* Action buttons */}
        <div className="flex items-center gap-2">
          <button
            data-testid="graph-fit-btn"
            onClick={handleFitView}
            className="flex-1 rounded-md border border-border bg-bg-tertiary px-3 py-1.5 text-xs text-text-primary hover:bg-bg-surface"
            title="Fit to view"
          >
            <Maximize2 className="mx-auto h-3.5 w-3.5" />
          </button>
          <button
            data-testid="graph-reset-btn"
            onClick={handleReset}
            className="flex-1 rounded-md border border-border bg-bg-tertiary px-3 py-1.5 text-xs text-text-primary hover:bg-bg-surface"
            title="Reset layout"
          >
            <RotateCcw className="mx-auto h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      {/* -------------------------------------------------------------- */}
      {/* Attack Paths Panel (below controls when toggled on)             */}
      {/* -------------------------------------------------------------- */}
      {showPaths && attackPaths.length > 0 && (
        <div
          data-testid="graph-path-list"
          className="absolute top-[22rem] right-4 z-10 w-64 max-h-60 overflow-y-auto rounded-lg border border-border bg-bg-secondary p-3 shadow-lg space-y-1"
        >
          <span className="text-[10px] uppercase tracking-wider text-text-muted">
            Attack Paths ({attackPaths.length})
          </span>
          {attackPaths.map((path) => (
            <button
              key={path.id}
              data-testid={`graph-path-item-${path.id}`}
              onClick={() => handlePathClick(path.id)}
              className={`w-full rounded-md px-2 py-1.5 text-left text-xs transition-colors ${
                selectedPathId === path.id
                  ? "border border-danger/50 bg-danger/15 text-danger"
                  : "border border-transparent bg-bg-tertiary text-text-secondary hover:bg-bg-surface"
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="truncate">{path.description || `Path ${path.id}`}</span>
                <span
                  className="ml-2 shrink-0 rounded px-1 py-0.5 text-[10px] font-semibold uppercase"
                  style={{ color: SEVERITY_COLORS[path.severity] || "#6b7280" }}
                >
                  {path.severity}
                </span>
              </div>
              <span className="text-[10px] text-text-muted">
                {path.steps.length} step{path.steps.length !== 1 ? "s" : ""}
              </span>
            </button>
          ))}
        </div>
      )}

      {/* -------------------------------------------------------------- */}
      {/* Detail Sidebar — slides from right                              */}
      {/* -------------------------------------------------------------- */}
      <div
        data-testid="graph-detail-sidebar"
        className={`absolute top-0 right-0 z-20 h-full w-80 border-l border-border bg-bg-secondary shadow-xl transition-transform duration-300 ease-in-out ${
          sidebarOpen && selectedNode ? "translate-x-0" : "translate-x-full"
        }`}
      >
        {selectedNode && (
          <div className="flex h-full flex-col p-4">
            {/* Header */}
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-semibold text-text-primary truncate pr-2">
                {selectedNode.label}
              </h3>
              <button
                data-testid="graph-detail-close"
                onClick={() => {
                  setSidebarOpen(false);
                  setSelectedNode(null);
                }}
                className="rounded p-1 text-text-muted hover:bg-bg-tertiary hover:text-text-primary"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            {/* Node info */}
            <div className="space-y-3 overflow-y-auto flex-1">
              {/* Type badge */}
              <div className="flex items-center gap-2">
                <span className="text-xs text-text-muted">Type</span>
                <span className="rounded bg-bg-tertiary px-2 py-0.5 text-xs font-mono text-text-primary capitalize">
                  {selectedNode.nodeType}
                </span>
              </div>

              {/* Connected nodes */}
              <div className="flex items-center gap-2">
                <span className="text-xs text-text-muted">Connected Nodes</span>
                <span className="font-mono text-xs text-text-primary">
                  {selectedNode.connectedCount}
                </span>
              </div>

              {/* Asset-specific info */}
              {(selectedNode.nodeType === "subdomain" ||
                selectedNode.nodeType === "ip" ||
                selectedNode.nodeType === "cidr") && (
                <>
                  {selectedNode.ports !== undefined && (
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-text-muted">Ports</span>
                      <span className="font-mono text-xs text-text-primary">
                        {selectedNode.ports}
                      </span>
                    </div>
                  )}
                  {selectedNode.vulnCount !== undefined && (
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-text-muted">Vulnerabilities</span>
                      <span className="font-mono text-xs text-text-primary">
                        {selectedNode.vulnCount}
                      </span>
                    </div>
                  )}
                </>
              )}

              {/* Vulnerability-specific info */}
              {selectedNode.nodeType === "vulnerability" && (
                <>
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-text-muted">Severity</span>
                    <span
                      className="rounded px-2 py-0.5 text-xs font-semibold uppercase"
                      style={{
                        color: SEVERITY_COLORS[selectedNode.severity || "info"] || "#6b7280",
                      }}
                    >
                      {selectedNode.severity ?? "info"}
                    </span>
                  </div>
                  {selectedNode.title && (
                    <div>
                      <span className="text-xs text-text-muted">Title</span>
                      <p className="mt-0.5 text-xs text-text-primary">
                        {selectedNode.title}
                      </p>
                    </div>
                  )}
                  {selectedNode.description && (
                    <div>
                      <span className="text-xs text-text-muted">Description</span>
                      <p className="mt-0.5 text-xs text-text-secondary leading-relaxed">
                        {selectedNode.description}
                      </p>
                    </div>
                  )}
                </>
              )}
            </div>

            {/* Shield icon at bottom */}
            <div className="mt-4 border-t border-border pt-3 text-center">
              <Shield className="mx-auto h-5 w-5 text-text-muted" />
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Page wrapper with ReactFlowProvider                                 */
/* ------------------------------------------------------------------ */

export default function GraphPage() {
  return (
    <ReactFlowProvider>
      <AttackGraphInner />
    </ReactFlowProvider>
  );
}
