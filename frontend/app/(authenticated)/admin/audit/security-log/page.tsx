"use client";

import { useState, useCallback, useMemo } from "react";
import { useAuthAuditTimelineItems }
  from "@/features/masteradmin/audit/security/auth_audit.react.query";
import type {
  AuthAuditFilterRequest,
  AuthAuditTimelineItemDTO,
} from "@/features/masteradmin/audit/security/auth_audit.types";
import { TopBar }
  from "@/features/masteradmin/audit/security/components/TopBar";
import { StatsStrip, deriveSecurityStats }
  from "@/features/masteradmin/audit/security/components/StatsStrip";
import { FilterBar }
  from "@/features/masteradmin/audit/security/components/FilterBar";
import { TimelineRail }
  from "@/features/masteradmin/audit/security/components/TimelineRail";
import { Inspector }
  from "@/features/masteradmin/audit/security/components/Inspector";

// ─── Constants ────────────────────────────────────────────────────────────────

const PAGE_SIZE = 50;

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function AuditAuthPage() {
  const [filter,        setFilter]        = useState<AuthAuditFilterRequest>({ page: 0, size: PAGE_SIZE });
  const [selectedItem,  setSelectedItem]  = useState<AuthAuditTimelineItemDTO | null>(null);
  const [inspectorOpen, setInspectorOpen] = useState(false); // mobile slide-over only

  // ── Filter update — always resets to page 0 and clears selection ──────────
  const updateFilter = useCallback((patch: Partial<AuthAuditFilterRequest>) => {
    setFilter((prev) => ({ ...prev, ...patch, page: 0 }));
    setSelectedItem(null);
  }, []);

  // ── Data ─────────────────────────────────────────────────────────────────
  const { data: response, isLoading, isFetching } =
    useAuthAuditTimelineItems(filter);

  const items         = response?.data                      ?? [];
  const totalElements = response?.pagination?.totalElements ?? 0;
  const totalPages    = response?.pagination?.totalPages    ?? 0;

  // ── Stats (page-scoped) ──────────────────────────────────────────────────
  const stats = useMemo(
    () => deriveSecurityStats(items, totalElements),
    [items, totalElements],
  );

  // ── Selection ────────────────────────────────────────────────────────────
  const handleSelectItem = useCallback((item: AuthAuditTimelineItemDTO) => {
    setSelectedItem((prev) => (prev?.id === item.id ? null : item));
    setInspectorOpen(true);
  }, []);

  // ── Clear ────────────────────────────────────────────────────────────────
  const clearFilters = useCallback(() => {
    setFilter({ page: 0, size: PAGE_SIZE });
    setSelectedItem(null);
  }, []);

  const hasActiveFilters = !!(
    filter.eventType  ||
    filter.userEmail  ||
    filter.ipAddress  ||
    filter.requestId  ||
    filter.success != null ||
    filter.from       ||
    filter.to
  );

  // ─── Render ──────────────────────────────────────────────────────────────

  return (
    <div className="flex h-screen flex-col bg-surface font-body overflow-hidden">

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

      {/* ── Main body — Timeline + Inspector ─────────────────────────── */}
      <div className="flex flex-1 overflow-hidden min-h-0 relative">

        {/* Left rail — Timeline */}
        <div
          className={`
            w-full md:w-3/5 overflow-y-auto border-r border-gs-line bg-surface
            transition-transform duration-300
            ${inspectorOpen
              ? "-translate-x-full md:translate-x-0 absolute md:relative inset-0"
              : ""}
          `}
        >
          <TimelineRail
            items={items}
            isLoading={isLoading}
            selectedItem={selectedItem}
            onSelect={handleSelectItem}
          />
        </div>

        {/* Right rail — Inspector */}
        <div
          className={`
            w-full md:w-2/5 overflow-y-auto bg-surface-2/30
            transition-transform duration-300
            ${inspectorOpen
              ? "translate-x-0 absolute md:relative inset-0"
              : "translate-x-full md:translate-x-0 absolute md:relative inset-0"}
          `}
        >
          {/* Mobile back button */}
          {inspectorOpen && (
            <div className="sticky top-0 z-10 flex items-center gap-2 p-3 border-b border-gs-line bg-surface-card md:hidden">
              <button
                onClick={() => setInspectorOpen(false)}
                className="font-body flex items-center gap-1.5 text-xs text-t3 hover:text-t1 transition-colors"
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