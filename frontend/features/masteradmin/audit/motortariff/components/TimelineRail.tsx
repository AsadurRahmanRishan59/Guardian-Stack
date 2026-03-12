"use client";

import { cn } from "@/lib/utils";
import { Skeleton } from "@/components/ui/skeleton";
import type { MotorTariffAuditTimelineItemDTO, RevisionType } from "@/features/masteradmin/audit/motortariff/motortariff_audit_types";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function formatTs(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleString("en-GB", {
    year: "2-digit", month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}

function RevBadge({ type }: { type: RevisionType }) {
  const cfg: Record<RevisionType, { label: string; cls: string }> = {
    CREATED:  { label: "NEW",  cls: "bg-gs-green-bg    text-gs-green   border-gs-green/30" },
    MODIFIED: { label: "MOD",  cls: "bg-brand-soft     text-brand      border-brand/30"    },
    DELETED:  { label: "DEL",  cls: "bg-destructive/10 text-destructive border-destructive/30" },
  };
  const { label, cls } = cfg[type] ?? { label: type, cls: "bg-surface-3 text-t3 border-gs-line" };
  return (
    <span className={cn("inline-flex items-center h-4 px-1.5 rounded-[3px] border text-[9px] font-bold font-body tracking-widest uppercase", cls)}>
      {label}
    </span>
  );
}

// ─── Node ─────────────────────────────────────────────────────────────────────

function TimelineNode({
  item,
  isSelected,
  onSelect,
}: {
  item:       MotorTariffAuditTimelineItemDTO;
  isSelected: boolean;
  onSelect:   (item: MotorTariffAuditTimelineItemDTO) => void;
}) {
  return (
    <button
      onClick={() => onSelect(item)}
      className={cn(
        "w-full text-left px-4 py-3 border-b border-gs-line transition-colors",
        "hover:bg-surface-2/60 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-brand",
        isSelected && "bg-brand-soft border-l-2 border-l-brand",
        !item.isActive && item.revisionType !== "DELETED" && "opacity-75",
      )}
    >
      <div className="flex items-center gap-2 mb-1">
        {/* Dot */}
        <span className={cn(
          "h-1.5 w-1.5 rounded-full shrink-0",
          item.revisionType === "CREATED"  && "bg-gs-green",
          item.revisionType === "MODIFIED" && "bg-brand",
          item.revisionType === "DELETED"  && "bg-destructive",
        )} />

        <RevBadge type={item.revisionType} />

        {/* Status changed badge */}
        {item.statusChanged && (
          <span className="inline-flex items-center h-4 px-1.5 rounded-[3px] border bg-amber-500/10 text-amber-600 border-amber-500/30 text-[9px] font-bold font-body tracking-widest uppercase">
            STATUS
          </span>
        )}

        {/* Inactive badge */}
        {!item.isActive && (
          <span className="inline-flex items-center h-4 px-1.5 rounded-[3px] border bg-surface-3 text-t4 border-gs-line text-[9px] font-body">
            inactive
          </span>
        )}

        <span className="ml-auto font-body text-[10px] text-t4 tabular-nums shrink-0">
          #{item.revisionNumber}
        </span>
      </div>

      {/* Tariff identity */}
      <div className="ml-3.5 space-y-0.5">
        <p className="font-body text-xs text-t1 font-medium leading-snug truncate">
          {item.tariffType} · {item.groupOfVehicle}
        </p>
        <p className="font-body text-[11px] text-t3 truncate">
          {item.typeOfVehicle} · {item.category}
        </p>
        <div className="flex items-center gap-2 pt-0.5">
          <span className="font-body text-[10px] text-t4">
            {formatTs(item.timestamp)}
          </span>
          {item.changedBy && (
            <span className="font-body text-[10px] text-t4 truncate">
              by {item.changedBy}
            </span>
          )}
        </div>
      </div>
    </button>
  );
}

// ─── Empty ────────────────────────────────────────────────────────────────────

function TimelineEmpty() {
  return (
    <div className="flex flex-col items-center justify-center gap-3 py-20 px-8 text-center">
      <span className="text-3xl">📋</span>
      <p className="font-body text-sm text-t3">No audit events match your filters.</p>
    </div>
  );
}

// ─── TimelineRail ─────────────────────────────────────────────────────────────

interface TimelineRailProps {
  items:        MotorTariffAuditTimelineItemDTO[];
  isLoading:    boolean;
  selectedItem: MotorTariffAuditTimelineItemDTO | null;
  onSelect:     (item: MotorTariffAuditTimelineItemDTO) => void;
}

export function TimelineRail({ items, isLoading, selectedItem, onSelect }: TimelineRailProps) {
  if (isLoading) {
    return (
      <div className="p-4 space-y-3">
        {Array.from({ length: 8 }).map((_, i) => (
          <div key={i} className="space-y-1.5">
            <Skeleton className="h-3 w-24 rounded" />
            <Skeleton className="h-3 w-48 rounded" />
            <Skeleton className="h-3 w-36 rounded" />
          </div>
        ))}
      </div>
    );
  }

  if (items.length === 0) return <TimelineEmpty />;

  return (
    <div className="divide-y divide-gs-line">
      {items.map((item) => (
        <TimelineNode
          key={item.revisionNumber}
          item={item}
          isSelected={selectedItem?.revisionNumber === item.revisionNumber}
          onSelect={onSelect}
        />
      ))}
    </div>
  );
}