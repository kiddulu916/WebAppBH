"use client";

import { useState } from "react";
import {
  ChevronRight,
  ChevronDown,
  Globe,
  Server,
  Network,
  Link2,
  Hash,
} from "lucide-react";

/* ------------------------------------------------------------------
 * Data shape — hierarchical tree built from flat DB records
 * ----------------------------------------------------------------*/

export interface TreeNode {
  id: string;
  label: string;
  type: "domain" | "subdomain" | "ip" | "port" | "endpoint" | "param";
  children?: TreeNode[];
  meta?: Record<string, unknown>;
}

const ICONS: Record<TreeNode["type"], React.ElementType> = {
  domain: Globe,
  subdomain: Globe,
  ip: Server,
  port: Network,
  endpoint: Link2,
  param: Hash,
};

/* ------------------------------------------------------------------
 * Single tree node (recursive)
 * ----------------------------------------------------------------*/

function TreeItem({
  node,
  depth = 0,
  onSelect,
}: {
  node: TreeNode;
  depth?: number;
  onSelect?: (nodeId: string) => void;
}) {
  const [open, setOpen] = useState(depth < 2);
  const hasChildren = (node.children?.length ?? 0) > 0;
  const Icon = ICONS[node.type] ?? Globe;

  function handleClick() {
    if (hasChildren) {
      setOpen(!open);
    }
    if (onSelect && node.id.startsWith("asset-")) {
      onSelect(node.id);
    }
  }

  return (
    <li>
      <button
        onClick={handleClick}
        className="flex w-full items-center gap-1.5 rounded px-2 py-1 text-sm transition-colors hover:bg-bg-surface"
        style={{ paddingLeft: `${depth * 16 + 8}px` }}
      >
        {hasChildren ? (
          open ? (
            <ChevronDown className="h-3.5 w-3.5 shrink-0 text-text-muted" />
          ) : (
            <ChevronRight className="h-3.5 w-3.5 shrink-0 text-text-muted" />
          )
        ) : (
          <span className="w-3.5" />
        )}
        <Icon className="h-3.5 w-3.5 shrink-0 text-accent" />
        <span className="truncate text-text-primary">{node.label}</span>
        {node.meta?.service != null && (
          <span className="ml-auto text-xs text-text-muted">
            {String(node.meta.service)}
          </span>
        )}
      </button>
      {open && hasChildren && (
        <ul>
          {node.children!.map((child) => (
            <TreeItem
              key={child.id}
              node={child}
              depth={depth + 1}
              onSelect={onSelect}
            />
          ))}
        </ul>
      )}
    </li>
  );
}

/* ------------------------------------------------------------------
 * Tree container
 * ----------------------------------------------------------------*/

export default function AssetTree({
  roots,
  onSelect,
}: {
  roots: TreeNode[];
  onSelect?: (nodeId: string) => void;
}) {
  if (roots.length === 0) {
    return (
      <div className="flex h-40 items-center justify-center text-sm text-text-muted">
        No assets discovered yet
      </div>
    );
  }

  return (
    <ul className="space-y-0.5 font-mono text-sm">
      {roots.map((node) => (
        <TreeItem key={node.id} node={node} onSelect={onSelect} />
      ))}
    </ul>
  );
}
