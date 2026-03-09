"use client";

// ─────────────────────────────────────────────────────────────────────────────
// Guardian Stack — Master Admin Forensic Audit Console
// Redesigned with shadcn/ui + Tailwind dark mode + extracted components
// ─────────────────────────────────────────────────────────────────────────────

import { useState, useCallback, useMemo } from "react";
import {
  useTimelineItems,
  useRevisionDetail,
} from "@/features/masteradmin/audit/user/user.react.query";
import type {
  AuditFilterRequest,
  AuditTimelineItemDTO,
} from "@/features/masteradmin/audit/user/user.types";
import { TopBar } from "@/features/masteradmin/audit/user/components/TopBar";
import { StatsStrip } from "@/features/masteradmin/audit/user/components/StatsStrip";
import { FilterBar } from "@/features/masteradmin/audit/user/components/FilterBar";
import { TimelineRail } from "@/features/masteradmin/audit/user/components/TimeLineRail";
import { Inspector } from "@/features/masteradmin/audit/user/components/Inspector";

// ─── Constants ───────────────────────────────────────────────────────────────

const PAGE_SIZE = 50;

// ─────────────────────────────────────────────────────────────────────────────
// MAIN PAGE
// ─────────────────────────────────────────────────────────────────────────────

export default function AuditUsersPage() {
  const [filter, setFilter] = useState<AuditFilterRequest>({
    page: 0,
    size: PAGE_SIZE,
  });
  const [selectedItem, setSelectedItem] = useState<AuditTimelineItemDTO | null>(
    null,
  );
  const [inspectorOpen, setInspectorOpen] = useState(false); // mobile: show inspector panel

  const updateFilter = useCallback((patch: Partial<AuditFilterRequest>) => {
    setFilter((prev) => ({ ...prev, ...patch, page: 0 }));
    setSelectedItem(null);
  }, []);

  const { data: response, isLoading, isFetching } = useTimelineItems(filter);

  // ✅ Reads from actual API shape: { data: [...], pagination: { ... } }
  const items = response?.data ?? [];
  const totalElements = response?.pagination?.totalElements ?? 0;
  const totalPages = response?.pagination?.totalPages ?? 0;

  const stats = useMemo(
    () => ({
      total: totalElements,
      critical: items.filter((i) => i.accountLocked || !i.enabled).length,
      escalations: items.filter((i) => i.hasAdminRoleEscalation).length,
      unknown: items.filter((i) => !isKnownIP(i.ipAddress)).length,
    }),
    [items, totalElements],
  );

  const handleSelectItem = useCallback((item: AuditTimelineItemDTO) => {
    setSelectedItem((prev) =>
      prev?.revisionNumber === item.revisionNumber ? null : item,
    );
    setInspectorOpen(true);
  }, []);

  const clearFilters = useCallback(() => {
    setFilter({ page: 0, size: PAGE_SIZE });
    setSelectedItem(null);
  }, []);

  const hasActiveFilters = !!(
    filter.email ||
    filter.changedBy ||
    filter.ipAddress ||
    filter.revisionTypes
  );

  return (
    <div className="flex h-screen flex-col bg-background font-sans overflow-hidden">
      <TopBar isFetching={isFetching && !isLoading} />

      <StatsStrip stats={stats} />

      <FilterBar
        filter={filter}
        onUpdate={updateFilter}
        onClear={clearFilters}
        hasActiveFilters={hasActiveFilters}
        totalElements={totalElements}
        totalPages={totalPages}
        onPageChange={(page) => setFilter((f) => ({ ...f, page }))}
      />

      {/* ── Main body ── */}
      <div className="flex flex-1 overflow-hidden min-h-0 relative">
        {/* LEFT RAIL — Timeline */}
        <div
          className={`
            w-full md:w-3/5 overflow-y-auto border-r border-border
            transition-transform duration-300
            ${inspectorOpen ? "-translate-x-full md:translate-x-0 absolute md:relative inset-0" : ""}
          `}
        >
          <TimelineRail
            items={items}
            isLoading={isLoading}
            selectedItem={selectedItem}
            onSelect={handleSelectItem}
          />
        </div>

        {/* RIGHT RAIL — Inspector */}
        <div
          className={`
            w-full md:w-2/5 overflow-y-auto bg-muted/20
            transition-transform duration-300
            ${inspectorOpen ? "translate-x-0 absolute md:relative inset-0" : "translate-x-full md:translate-x-0 absolute md:relative inset-0"}
          `}
        >
          {/* Mobile back button */}
          {inspectorOpen && (
            <div className="sticky top-0 z-10 flex items-center gap-2 p-3 border-b border-border bg-background/95 backdrop-blur md:hidden">
              <button
                onClick={() => setInspectorOpen(false)}
                className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors"
              >
                ← Back to timeline
              </button>
            </div>
          )}
          <Inspector selectedItem={selectedItem} />
        </div>
      </div>
    </div>
  );
}

// ─── Helpers (shared across this module) ─────────────────────────────────────

export const TRUSTED_IP_PREFIXES = ["192.168.", "10.0.", "172.16."];

export function isKnownIP(ip: string) {
  return TRUSTED_IP_PREFIXES.some((p) => ip?.startsWith(p));
}
