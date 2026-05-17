// dashboard/src/components/assets/DirectoryTree.tsx
"use client";

import { useState } from "react";
import { ChevronRight, ChevronDown, Folder, File, Globe } from "lucide-react";
import type { PathNodeTree } from "@/lib/api";

const NODE_TYPE_ICON: Record<string, React.ReactNode> = {
  directory: <Folder className="h-3.5 w-3.5 text-neon-orange" />,
  file: <File className="h-3.5 w-3.5 text-text-secondary" />,
  sensitive_file: <File className="h-3.5 w-3.5 text-danger" />,
  form: <Globe className="h-3.5 w-3.5 text-neon-blue" />,
  url: <Globe className="h-3.5 w-3.5 text-text-muted" />,
};

const NODE_TYPE_BADGE: Record<string, string> = {
  directory: "bg-neon-orange/10 text-neon-orange border-neon-orange/20",
  file: "bg-bg-surface text-text-secondary border-border",
  sensitive_file: "bg-danger/10 text-danger border-danger/20",
  form: "bg-neon-blue-glow text-neon-blue border-neon-blue/20",
  url: "bg-bg-surface text-text-muted border-border",
};

function TreeNodeRow({
  node,
  selectedId,
  onSelect,
  depth,
}: {
  node: PathNodeTree;
  selectedId: number | null;
  onSelect: (id: number) => void;
  depth: number;
}) {
  const [open, setOpen] = useState(depth < 2);
  const hasChildren = node.children.length > 0;
  const isSelected = node.id === selectedId;
  const icon = NODE_TYPE_ICON[node.node_type ?? "url"] ?? NODE_TYPE_ICON.url;
  const badge = NODE_TYPE_BADGE[node.node_type ?? "url"] ?? NODE_TYPE_BADGE.url;

  return (
    <div>
      <div
        data-testid={`tree-node-${node.id}`}
        className={`flex cursor-pointer items-center gap-1.5 rounded px-2 py-1 text-sm transition-colors ${
          isSelected
            ? "bg-neon-orange/10 text-neon-orange"
            : "hover:bg-bg-tertiary text-text-primary"
        }`}
        style={{ paddingLeft: `${0.5 + depth * 1.25}rem` }}
        onClick={() => onSelect(node.id)}
      >
        <button
          onClick={(e) => {
            e.stopPropagation();
            if (hasChildren) setOpen((o) => !o);
          }}
          className="flex-shrink-0"
        >
          {hasChildren ? (
            open ? (
              <ChevronDown className="h-3.5 w-3.5 text-text-muted" />
            ) : (
              <ChevronRight className="h-3.5 w-3.5 text-text-muted" />
            )
          ) : (
            <span className="inline-block w-3.5" />
          )}
        </button>
        {icon}
        <span className="font-mono truncate">{node.path_segment}</span>
        {node.node_type && (
          <span
            className={`ml-auto flex-shrink-0 rounded border px-1.5 py-0 text-[10px] font-medium ${badge}`}
          >
            {node.node_type}
          </span>
        )}
      </div>
      {open && hasChildren && (
        <div>
          {node.children.map((child) => (
            <TreeNodeRow
              key={child.id}
              node={child}
              selectedId={selectedId}
              onSelect={onSelect}
              depth={depth + 1}
            />
          ))}
        </div>
      )}
    </div>
  );
}

export default function DirectoryTree({
  nodes,
  selectedId,
  onSelect,
}: {
  nodes: PathNodeTree[];
  selectedId: number | null;
  onSelect: (id: number) => void;
}) {
  if (nodes.length === 0) {
    return (
      <p className="py-8 text-center text-xs text-text-muted">
        No path hierarchy found. Run a scan to populate the directory tree.
      </p>
    );
  }

  return (
    <div className="font-mono text-sm">
      {nodes.map((node) => (
        <TreeNodeRow
          key={node.id}
          node={node}
          selectedId={selectedId}
          onSelect={onSelect}
          depth={0}
        />
      ))}
    </div>
  );
}
