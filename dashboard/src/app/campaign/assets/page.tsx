"use client";

import { useEffect, useState, useMemo, useCallback } from "react";
import { useRouter } from "next/navigation";
import {
  Loader2,
  Globe,
  Search,
  ArrowUpDown,
  ChevronLeft,
  ChevronRight,
  ChevronDown,
  ChevronUp,
  RefreshCw,
  AlertTriangle,
  Shield,
  Cloud,
  Network,
} from "lucide-react";
import { api, type AssetWithLocations } from "@/lib/api";
import { useCampaignStore } from "@/stores/campaign";
import type { Location, Vulnerability, CloudAsset } from "@/types/schema";

/* ── Constants ── */

const PAGE_SIZE = 25;

const TYPE_BADGE: Record<string, string> = {
  subdomain: "bg-neon-blue-glow text-neon-blue border-neon-blue/20",
  ip: "bg-neon-orange-glow text-neon-orange border-neon-orange/20",
  cidr: "bg-neon-green-glow text-neon-green border-neon-green/20",
  url: "bg-bg-surface text-text-muted border-border",
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "text-danger bg-danger/10 border-danger/20",
  high: "text-neon-orange bg-neon-orange-glow border-neon-orange/20",
  medium: "text-sev-medium bg-sev-medium/10 border-sev-medium/20",
  low: "text-neon-blue bg-neon-blue-glow border-neon-blue/20",
  info: "text-text-muted bg-bg-surface border-border",
};

type SortKey = "asset_type" | "asset_value" | "source_tool" | "created_at" | "vuln_count" | "ports";
type SortDir = "asc" | "desc";
type TypeFilter = "all" | "subdomain" | "ip" | "cidr";
type DetailTab = "locations" | "vulns" | "cloud" | "tree";

/* ── Detail data stored per expanded row ── */

interface DetailData {
  locations: Location[];
  vulnerabilities: Vulnerability[];
  cloudAssets: CloudAsset[];
}

/* ── Helper: relative timestamp ── */

function relativeTime(iso: string | null): string {
  if (!iso) return "\u2014";
  const diff = Date.now() - new Date(iso).getTime();
  const seconds = Math.floor(diff / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

/* ── Helper: format ports ── */

function formatPorts(locations: AssetWithLocations["locations"]): { display: string; total: number } {
  const ports = locations.map((l) => l.port).filter((p) => p != null);
  const unique = [...new Set(ports)].sort((a, b) => a - b);
  if (unique.length === 0) return { display: "\u2014", total: 0 };
  if (unique.length <= 3) return { display: unique.join(", "), total: unique.length };
  return {
    display: `${unique.slice(0, 3).join(", ")} +${unique.length - 3} more`,
    total: unique.length,
  };
}

/* ── Main Page Component ── */

export default function AssetsPage() {
  const router = useRouter();
  const activeTarget = useCampaignStore((s) => s.activeTarget);

  /* ── Data state ── */
  const [data, setData] = useState<AssetWithLocations[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  /* ── Controls ── */
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState<TypeFilter>("all");
  const [sortKey, setSortKey] = useState<SortKey>("created_at");
  const [sortDir, setSortDir] = useState<SortDir>("desc");
  const [page, setPage] = useState(0);

  /* ── Expand state ── */
  const [expandedRow, setExpandedRow] = useState<number | null>(null);
  const [activeTab, setActiveTab] = useState<DetailTab>("locations");
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailData, setDetailData] = useState<DetailData | null>(null);

  /* ── Vuln counts cache (populated when detail is fetched) ── */
  const [vulnCounts, setVulnCounts] = useState<Record<number, { count: number; severity: string }>>({});

  /* ── Fetch assets ── */
  const fetchData = useCallback(async () => {
    if (!activeTarget) return;
    setLoading(true);
    setError(false);
    try {
      const res = await api.getAssets(activeTarget.id);
      setData(res.assets);
    } catch {
      setError(true);
    } finally {
      setLoading(false);
    }
  }, [activeTarget]);

  useEffect(() => {
    if (!activeTarget) {
      router.push("/");
      return;
    }
    fetchData();
  }, [activeTarget, router, fetchData]);

  /* ── Sort toggle ── */
  const toggleSort = useCallback(
    (key: SortKey) => {
      if (sortKey === key) {
        setSortDir((d) => (d === "asc" ? "desc" : "asc"));
      } else {
        setSortKey(key);
        setSortDir("asc");
      }
      setPage(0);
    },
    [sortKey],
  );

  /* ── Filtering + sorting ── */
  const filtered = useMemo(() => {
    let rows = data;

    // Type filter
    if (typeFilter !== "all") {
      rows = rows.filter((r) => r.asset_type === typeFilter);
    }

    // Text search
    if (search) {
      const q = search.toLowerCase();
      rows = rows.filter((r) => r.asset_value.toLowerCase().includes(q));
    }

    // Sort
    rows = [...rows].sort((a, b) => {
      let cmp = 0;
      switch (sortKey) {
        case "vuln_count": {
          const ac = vulnCounts[a.id]?.count ?? 0;
          const bc = vulnCounts[b.id]?.count ?? 0;
          cmp = ac - bc;
          break;
        }
        case "ports": {
          cmp = a.locations.length - b.locations.length;
          break;
        }
        default: {
          const av = a[sortKey as keyof AssetWithLocations] ?? "";
          const bv = b[sortKey as keyof AssetWithLocations] ?? "";
          cmp = String(av).localeCompare(String(bv));
        }
      }
      return sortDir === "asc" ? cmp : -cmp;
    });

    return rows;
  }, [data, search, typeFilter, sortKey, sortDir, vulnCounts]);

  /* ── Pagination ── */
  const pageCount = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const paged = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  /* ── Expand handler ── */
  const handleExpand = useCallback(
    async (assetId: number) => {
      if (expandedRow === assetId) {
        setExpandedRow(null);
        setDetailData(null);
        return;
      }

      setExpandedRow(assetId);
      setActiveTab("locations");
      setDetailLoading(true);
      setDetailData(null);

      try {
        const [locRes, vulnRes, cloudRes] = await Promise.all([
          api.getAssetLocations(assetId),
          api.getAssetVulnerabilities(assetId),
          api.getAssetCloud(assetId),
        ]);

        const detail: DetailData = {
          locations: locRes.locations,
          vulnerabilities: vulnRes.vulnerabilities,
          cloudAssets: cloudRes.cloud_assets,
        };

        setDetailData(detail);

        // Cache vuln count + highest severity
        if (vulnRes.vulnerabilities.length > 0) {
          const severityOrder = ["critical", "high", "medium", "low", "info"];
          const highest =
            vulnRes.vulnerabilities.reduce((acc, v) => {
              const ai = severityOrder.indexOf(acc);
              const vi = severityOrder.indexOf(v.severity);
              return vi < ai ? v.severity : acc;
            }, "info");
          setVulnCounts((prev) => ({
            ...prev,
            [assetId]: { count: vulnRes.vulnerabilities.length, severity: highest },
          }));
        } else {
          setVulnCounts((prev) => ({
            ...prev,
            [assetId]: { count: 0, severity: "info" },
          }));
        }
      } catch {
        // Detail fetch failed — show empty
        setDetailData({ locations: [], vulnerabilities: [], cloudAssets: [] });
      } finally {
        setDetailLoading(false);
      }
    },
    [expandedRow],
  );

  /* ── No active target guard ── */
  if (!activeTarget) {
    return (
      <div className="flex h-64 items-center justify-center">
        <p className="text-text-muted">No active campaign selected.</p>
      </div>
    );
  }

  /* ── Error state ── */
  if (error && !loading) {
    return (
      <div className="space-y-5 animate-fade-in">
        <PageHeader count={0} />
        <div
          data-testid="assets-error-state"
          className="flex flex-col items-center justify-center gap-4 rounded-lg border border-danger/30 bg-danger/5 py-16"
        >
          <AlertTriangle className="h-10 w-10 text-danger" />
          <p className="text-text-primary font-medium">Failed to load assets.</p>
          <button
            data-testid="assets-retry-btn"
            onClick={fetchData}
            className="flex items-center gap-2 rounded-md border border-border bg-bg-surface px-4 py-2 text-sm text-text-primary transition-colors hover:bg-bg-tertiary"
          >
            <RefreshCw className="h-4 w-4" />
            Retry
          </button>
        </div>
      </div>
    );
  }

  /* ── Loading state ── */
  if (loading) {
    return (
      <div className="space-y-5 animate-fade-in">
        <PageHeader count={0} />
        <div className="flex h-64 items-center justify-center">
          <Loader2 className="h-6 w-6 animate-spin text-neon-orange" />
        </div>
      </div>
    );
  }

  /* ── Empty state ── */
  if (data.length === 0) {
    return (
      <div className="space-y-5 animate-fade-in">
        <PageHeader count={0} />
        <div
          data-testid="assets-empty-state"
          className="flex flex-col items-center justify-center gap-3 rounded-lg border border-border bg-bg-secondary py-16"
        >
          <Globe className="h-10 w-10 text-text-muted" />
          <p className="text-text-muted text-sm text-center max-w-md">
            No assets discovered yet. Create a target and run a scan to start discovering assets.
          </p>
        </div>
      </div>
    );
  }

  /* ── Main render ── */
  return (
    <div className="space-y-5 animate-fade-in">
      <PageHeader count={filtered.length} />

      {/* Controls: Search + Type Filter */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-text-muted" />
          <input
            data-testid="assets-search"
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setPage(0);
            }}
            placeholder="Search by hostname or IP..."
            className="w-full rounded-md border border-border bg-bg-tertiary py-2 pl-9 pr-3 text-sm text-text-primary placeholder:text-text-muted input-focus"
          />
        </div>
        <select
          data-testid="assets-type-filter"
          value={typeFilter}
          onChange={(e) => {
            setTypeFilter(e.target.value as TypeFilter);
            setPage(0);
          }}
          className="rounded-md border border-border bg-bg-tertiary px-3 py-2 text-sm text-text-primary input-focus"
        >
          <option value="all">All Types</option>
          <option value="subdomain">Subdomain</option>
          <option value="ip">IP</option>
          <option value="cidr">CIDR</option>
        </select>
      </div>

      {/* Table */}
      <div data-testid="assets-table" className="overflow-x-auto rounded-lg border border-border">
        <table className="w-full text-left text-sm">
          <thead className="bg-bg-surface text-xs text-text-secondary">
            <tr>
              <th className="w-10 px-2 py-3" />
              <SortHeader label="Type" field="asset_type" current={sortKey} dir={sortDir} onSort={toggleSort} />
              <SortHeader label="Hostname / IP" field="asset_value" current={sortKey} dir={sortDir} onSort={toggleSort} />
              <SortHeader label="Ports" field="ports" current={sortKey} dir={sortDir} onSort={toggleSort} />
              <SortHeader label="Vulns" field="vuln_count" current={sortKey} dir={sortDir} onSort={toggleSort} />
              <SortHeader label="Source Tool" field="source_tool" current={sortKey} dir={sortDir} onSort={toggleSort} />
              <SortHeader label="Discovered" field="created_at" current={sortKey} dir={sortDir} onSort={toggleSort} />
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {paged.length === 0 ? (
              <tr>
                <td colSpan={7} className="px-4 py-8 text-center text-text-muted">
                  No assets match the current filters.
                </td>
              </tr>
            ) : (
              paged.map((row) => {
                const isExpanded = expandedRow === row.id;
                const ports = formatPorts(row.locations);
                const vc = vulnCounts[row.id];

                return (
                  <AssetRowGroup
                    key={row.id}
                    row={row}
                    isExpanded={isExpanded}
                    ports={ports}
                    vulnInfo={vc}
                    activeTab={activeTab}
                    detailLoading={detailLoading}
                    detailData={isExpanded ? detailData : null}
                    onExpand={handleExpand}
                    onTabChange={setActiveTab}
                    activeTarget={activeTarget}
                  />
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <div data-testid="assets-pagination" className="flex items-center justify-between text-xs text-text-muted">
        <span>{filtered.length} result(s)</span>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setPage((p) => Math.max(0, p - 1))}
            disabled={page === 0}
            className="rounded p-1 hover:bg-bg-surface disabled:opacity-30"
          >
            <ChevronLeft className="h-4 w-4" />
          </button>
          <span className="font-mono">
            {page + 1} / {pageCount}
          </span>
          <button
            onClick={() => setPage((p) => Math.min(pageCount - 1, p + 1))}
            disabled={page >= pageCount - 1}
            className="rounded p-1 hover:bg-bg-surface disabled:opacity-30"
          >
            <ChevronRight className="h-4 w-4" />
          </button>
        </div>
      </div>
    </div>
  );
}

/* ── Page Header (extracted for reuse across states) ── */

function PageHeader({ count }: { count: number }) {
  return (
    <div className="flex items-center justify-between">
      <div>
        <h1 className="flex items-center gap-2 text-2xl font-bold text-text-primary">
          <Globe className="h-5 w-5 text-neon-blue" />
          Assets
        </h1>
        <p className="mt-1 text-sm text-text-secondary">
          Discovered subdomains, IPs, and CIDRs
        </p>
      </div>
      <span className="rounded-md border border-border bg-bg-surface px-3 py-1 font-mono text-sm text-text-primary">
        {count}
      </span>
    </div>
  );
}

/* ── Sort Header ── */

function SortHeader({
  label,
  field,
  current,
  dir,
  onSort,
}: {
  label: string;
  field: SortKey;
  current: SortKey;
  dir: SortDir;
  onSort: (k: SortKey) => void;
}) {
  const active = current === field;
  return (
    <th className="px-4 py-3 font-medium">
      <button className="flex items-center gap-1" onClick={() => onSort(field)}>
        {label}
        <ArrowUpDown className={`h-3 w-3 ${active ? "text-neon-orange" : "text-text-muted"}`} />
        {active && (
          <span className="text-[10px] text-neon-orange">{dir === "asc" ? "\u2191" : "\u2193"}</span>
        )}
      </button>
    </th>
  );
}

/* ── Asset Row + Detail Panel Group ── */

function AssetRowGroup({
  row,
  isExpanded,
  ports,
  vulnInfo,
  activeTab,
  detailLoading,
  detailData,
  onExpand,
  onTabChange,
  activeTarget,
}: {
  row: AssetWithLocations;
  isExpanded: boolean;
  ports: { display: string; total: number };
  vulnInfo: { count: number; severity: string } | undefined;
  activeTab: DetailTab;
  detailLoading: boolean;
  detailData: DetailData | null;
  onExpand: (id: number) => void;
  onTabChange: (tab: DetailTab) => void;
  activeTarget: { id: number; base_domain: string; company_name: string };
}) {
  const vulnCount = vulnInfo?.count ?? 0;
  const highSev = vulnInfo?.severity ?? "info";

  return (
    <>
      <tr
        data-testid={`asset-row-${row.id}`}
        className={`bg-bg-secondary transition-colors hover:bg-bg-tertiary ${
          isExpanded ? "bg-bg-tertiary" : ""
        }`}
      >
        {/* Expand button */}
        <td className="px-2 py-2.5">
          <button
            data-testid={`asset-expand-btn-${row.id}`}
            onClick={() => onExpand(row.id)}
            className="rounded p-1 hover:bg-bg-surface transition-colors"
            aria-label={isExpanded ? "Collapse row" : "Expand row"}
          >
            {isExpanded ? (
              <ChevronUp className="h-4 w-4 text-neon-orange" />
            ) : (
              <ChevronDown className="h-4 w-4 text-text-muted" />
            )}
          </button>
        </td>

        {/* Type badge */}
        <td className="px-4 py-2.5">
          <span
            className={`inline-block rounded border px-2 py-0.5 text-xs font-medium ${
              TYPE_BADGE[row.asset_type] ?? TYPE_BADGE.url
            }`}
          >
            {row.asset_type}
          </span>
        </td>

        {/* Hostname / IP */}
        <td className="px-4 py-2.5 font-mono text-text-primary">{row.asset_value}</td>

        {/* Ports */}
        <td className="px-4 py-2.5 font-mono text-xs text-text-secondary">{ports.display}</td>

        {/* Vuln Count */}
        <td className="px-4 py-2.5">
          <span
            data-testid={`asset-vuln-badge-${row.id}`}
            className={`inline-block rounded border px-2 py-0.5 text-xs font-medium ${
              vulnCount > 0 ? SEVERITY_COLORS[highSev] ?? SEVERITY_COLORS.info : "text-text-muted bg-bg-surface border-border"
            }`}
          >
            {vulnCount}
          </span>
        </td>

        {/* Source Tool */}
        <td className="px-4 py-2.5 font-mono text-xs text-text-secondary">
          {row.source_tool ?? "\u2014"}
        </td>

        {/* Discovered At */}
        <td className="px-4 py-2.5 font-mono text-xs text-text-muted">
          {relativeTime(row.created_at)}
        </td>
      </tr>

      {/* ── Expandable detail panel ── */}
      {isExpanded && (
        <tr>
          <td colSpan={7} className="p-0">
            <div
              data-testid={`asset-detail-panel-${row.id}`}
              className="border-t border-border bg-bg-primary px-6 py-4"
            >
              {/* Tabs */}
              <div className="mb-4 flex gap-1 rounded-md bg-bg-surface p-1 w-fit">
                <TabButton
                  testId="asset-tab-locations"
                  active={activeTab === "locations"}
                  onClick={() => onTabChange("locations")}
                  icon={<Network className="h-3.5 w-3.5" />}
                  label="Locations"
                />
                <TabButton
                  testId="asset-tab-vulns"
                  active={activeTab === "vulns"}
                  onClick={() => onTabChange("vulns")}
                  icon={<Shield className="h-3.5 w-3.5" />}
                  label="Vulnerabilities"
                />
                <TabButton
                  testId="asset-tab-cloud"
                  active={activeTab === "cloud"}
                  onClick={() => onTabChange("cloud")}
                  icon={<Cloud className="h-3.5 w-3.5" />}
                  label="Cloud"
                />
                <TabButton
                  testId="asset-tab-tree"
                  active={activeTab === "tree"}
                  onClick={() => onTabChange("tree")}
                  icon={<Globe className="h-3.5 w-3.5" />}
                  label="Tree"
                />
              </div>

              {/* Tab content */}
              {detailLoading ? (
                <div className="flex h-24 items-center justify-center">
                  <Loader2 className="h-5 w-5 animate-spin text-neon-orange" />
                </div>
              ) : detailData ? (
                <>
                  {activeTab === "locations" && <LocationsTab locations={detailData.locations} />}
                  {activeTab === "vulns" && <VulnerabilitiesTab vulnerabilities={detailData.vulnerabilities} />}
                  {activeTab === "cloud" && <CloudTab cloudAssets={detailData.cloudAssets} />}
                  {activeTab === "tree" && (
                    <TreeTab
                      asset={row}
                      locations={detailData.locations}
                      targetDomain={activeTarget.base_domain}
                    />
                  )}
                </>
              ) : null}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

/* ── Tab Button ── */

function TabButton({
  testId,
  active,
  onClick,
  icon,
  label,
}: {
  testId: string;
  active: boolean;
  onClick: () => void;
  icon: React.ReactNode;
  label: string;
}) {
  return (
    <button
      data-testid={testId}
      onClick={onClick}
      className={`flex items-center gap-1.5 rounded px-3 py-1.5 text-xs font-medium transition-colors ${
        active
          ? "bg-bg-tertiary text-neon-orange shadow-sm"
          : "text-text-muted hover:text-text-secondary"
      }`}
    >
      {icon}
      {label}
    </button>
  );
}

/* ── Locations Tab ── */

function LocationsTab({ locations }: { locations: Location[] }) {
  if (locations.length === 0) {
    return <p className="py-4 text-center text-xs text-text-muted">No locations found.</p>;
  }

  return (
    <div className="overflow-x-auto rounded border border-border">
      <table className="w-full text-left text-xs">
        <thead className="bg-bg-surface text-text-secondary">
          <tr>
            <th className="px-3 py-2 font-medium">Port</th>
            <th className="px-3 py-2 font-medium">Protocol</th>
            <th className="px-3 py-2 font-medium">Service</th>
            <th className="px-3 py-2 font-medium">State</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {locations.map((loc) => (
            <tr key={loc.id} className="bg-bg-secondary hover:bg-bg-tertiary transition-colors">
              <td className="px-3 py-1.5 font-mono text-text-primary">{loc.port}</td>
              <td className="px-3 py-1.5 text-text-secondary">{loc.protocol ?? "\u2014"}</td>
              <td className="px-3 py-1.5 font-mono text-text-secondary">{loc.service ?? "\u2014"}</td>
              <td className="px-3 py-1.5">
                <span
                  className={`inline-block rounded border px-1.5 py-0.5 text-[10px] font-medium ${
                    loc.state === "open"
                      ? "bg-neon-green-glow text-neon-green border-neon-green/20"
                      : "bg-bg-surface text-text-muted border-border"
                  }`}
                >
                  {loc.state ?? "\u2014"}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/* ── Vulnerabilities Tab ── */

function VulnerabilitiesTab({ vulnerabilities }: { vulnerabilities: Vulnerability[] }) {
  if (vulnerabilities.length === 0) {
    return <p className="py-4 text-center text-xs text-text-muted">No vulnerabilities found.</p>;
  }

  return (
    <div className="overflow-x-auto rounded border border-border">
      <table className="w-full text-left text-xs">
        <thead className="bg-bg-surface text-text-secondary">
          <tr>
            <th className="px-3 py-2 font-medium">Severity</th>
            <th className="px-3 py-2 font-medium">Title</th>
            <th className="px-3 py-2 font-medium">Source Tool</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {vulnerabilities.map((vuln) => (
            <tr key={vuln.id} className="bg-bg-secondary hover:bg-bg-tertiary transition-colors">
              <td className="px-3 py-1.5">
                <span
                  className={`inline-block rounded border px-1.5 py-0.5 text-[10px] font-medium uppercase ${
                    SEVERITY_COLORS[vuln.severity] ?? SEVERITY_COLORS.info
                  }`}
                >
                  {vuln.severity}
                </span>
              </td>
              <td className="px-3 py-1.5 text-text-primary">{vuln.title}</td>
              <td className="px-3 py-1.5 font-mono text-text-secondary">{vuln.source_tool ?? "\u2014"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/* ── Cloud Tab ── */

function CloudTab({ cloudAssets }: { cloudAssets: CloudAsset[] }) {
  if (cloudAssets.length === 0) {
    return <p className="py-4 text-center text-xs text-text-muted">No cloud assets found.</p>;
  }

  return (
    <div className="overflow-x-auto rounded border border-border">
      <table className="w-full text-left text-xs">
        <thead className="bg-bg-surface text-text-secondary">
          <tr>
            <th className="px-3 py-2 font-medium">Provider</th>
            <th className="px-3 py-2 font-medium">Type</th>
            <th className="px-3 py-2 font-medium">URL</th>
            <th className="px-3 py-2 font-medium">Public?</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {cloudAssets.map((ca) => (
            <tr key={ca.id} className="bg-bg-secondary hover:bg-bg-tertiary transition-colors">
              <td className="px-3 py-1.5 text-text-primary">{ca.provider}</td>
              <td className="px-3 py-1.5 text-text-secondary">{ca.asset_type}</td>
              <td className="px-3 py-1.5 font-mono text-text-secondary truncate max-w-xs">
                {ca.url ?? "\u2014"}
              </td>
              <td className="px-3 py-1.5">
                <span
                  className={`inline-block rounded border px-1.5 py-0.5 text-[10px] font-medium ${
                    ca.is_public
                      ? "bg-danger/10 text-danger border-danger/20"
                      : "bg-neon-green-glow text-neon-green border-neon-green/20"
                  }`}
                >
                  {ca.is_public ? "YES" : "NO"}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/* ── Tree View Tab ── */

function TreeTab({
  asset,
  locations,
  targetDomain,
}: {
  asset: AssetWithLocations;
  locations: Location[];
  targetDomain: string;
}) {
  return (
    <div className="space-y-1 font-mono text-xs">
      {/* Target (root) */}
      <div className="text-text-primary">
        <span className="text-neon-blue">\u25C6</span> {targetDomain}
      </div>

      {/* Domain / asset */}
      <div className="ml-4 text-text-primary">
        <span className="text-neon-orange">\u251C\u2500</span>{" "}
        <span
          className={`inline-block rounded border px-1.5 py-0.5 text-[10px] font-medium ${
            TYPE_BADGE[asset.asset_type] ?? TYPE_BADGE.url
          }`}
        >
          {asset.asset_type}
        </span>{" "}
        {asset.asset_value}
      </div>

      {/* Ports (children) */}
      {locations.length > 0 ? (
        locations.map((loc, i) => {
          const isLast = i === locations.length - 1;
          return (
            <div key={loc.id} className="ml-8 text-text-secondary">
              <span className="text-text-muted">{isLast ? "\u2514\u2500" : "\u251C\u2500"}</span>{" "}
              :{loc.port}
              {loc.service ? ` (${loc.service})` : ""}
              {loc.state ? (
                <span
                  className={`ml-1 ${
                    loc.state === "open" ? "text-neon-green" : "text-text-muted"
                  }`}
                >
                  [{loc.state}]
                </span>
              ) : null}
            </div>
          );
        })
      ) : (
        <div className="ml-8 text-text-muted">
          <span className="text-text-muted">{"\u2514\u2500"}</span> (no ports discovered)
        </div>
      )}
    </div>
  );
}
