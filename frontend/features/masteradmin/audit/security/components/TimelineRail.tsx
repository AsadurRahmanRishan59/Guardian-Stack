"use client";

import { cn } from "@/lib/utils";
import { Skeleton } from "@/components/ui/skeleton";
import type { AuditLevel, AuthAuditTimelineItemDTO } from "../auth_audit.types";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function formatTs(iso: string): string {
  return new Date(iso).toLocaleString("en-GB", {
    month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}

// ─── Level badge ─────────────────────────────────────────────────────────────

const LEVEL_BADGE_CLS: Record<AuditLevel, string> = {
  DEBUG:    "bg-surface-3      text-t4          border-gs-line",
  INFO:     "bg-surface-3      text-t3          border-gs-line",
  WARN:     "bg-amber-500/10   text-amber-600   border-amber-500/30",
  CRITICAL: "bg-red-500/10     text-red-600     border-red-500/30",
};

function LevelBadge({ level }: { level: AuditLevel }) {
  return (
    <span
      className={cn(
        "inline-flex items-center h-4 px-1.5 rounded-[3px] border text-[9px] font-bold font-body tracking-widest uppercase",
        LEVEL_BADGE_CLS[level],
      )}
    >
      {level}
    </span>
  );
}

// ─── Outcome dot ─────────────────────────────────────────────────────────────

/** Rose for failure, Emerald for success — the primary visual signal. */
function OutcomeDot({ success }: { success: boolean }) {
  return (
    <span
      className={cn(
        "mt-0.5 h-2 w-2 shrink-0 rounded-full",
        success ? "bg-emerald-500" : "bg-rose-500",
      )}
    />
  );
}

// ─── TimelineNode ─────────────────────────────────────────────────────────────

interface TimelineNodeProps {
  item:       AuthAuditTimelineItemDTO;
  isSelected: boolean;
  onSelect:   (item: AuthAuditTimelineItemDTO) => void;
}

function TimelineNode({ item, isSelected, onSelect }: TimelineNodeProps) {
  return (
    <button
      onClick={() => onSelect(item)}
      className={cn(
        "w-full flex items-start gap-3 px-4 py-3 text-left transition-colors",
        isSelected
          ? item.success
            ? "bg-emerald-500/8 border-l-2 border-emerald-500"
            : "bg-rose-500/8    border-l-2 border-rose-500"
          : "border-l-2 border-transparent hover:bg-surface-2",
      )}
    >
      {/* Outcome indicator */}
      <OutcomeDot success={item.success} />

      <div className="flex-1 min-w-0">
        {/* Top row: event type + level badge + timestamp */}
        <div className="flex items-center gap-1.5 flex-wrap">
          <span
            className={cn(
              "font-body text-xs font-semibold",
              item.success ? "text-emerald-600" : "text-rose-600",
            )}
          >
            {item.eventType}
          </span>
          <LevelBadge level={item.level} />
          <span className="ml-auto font-body text-[10px] text-t4 tabular-nums shrink-0">
            {formatTs(item.timestamp)}
          </span>
        </div>

        {/* Description */}
        <p className="font-body text-[11px] text-t3 mt-0.5 truncate">
          {item.eventDescription}
        </p>

        {/* Identity row */}
        <div className="flex items-center gap-2 mt-0.5 flex-wrap">
          {item.userEmail && (
            <span className="font-body text-[10px] text-t4 truncate">
              {item.userEmail}
            </span>
          )}
          {item.ipAddress && (
            <span className="font-body text-[10px] text-t4 font-mono">
              {item.ipAddress}
            </span>
          )}
          {/* Failure reason preview */}
          {!item.success && item.failureReason && (
            <span className="font-body text-[10px] text-rose-500/80 truncate">
              · {item.failureReason}
            </span>
          )}
        </div>
      </div>
    </button>
  );
}

// ─── Empty state ─────────────────────────────────────────────────────────────

function TimelineEmpty() {
  return (
    <div className="flex flex-col items-center justify-center gap-3 py-20 px-8 text-center">
      <span className="text-3xl">🛡️</span>
      <p className="font-body text-sm text-t3">No security events match your filters.</p>
    </div>
  );
}

// ─── TimelineRail ─────────────────────────────────────────────────────────────

interface TimelineRailProps {
  items:        AuthAuditTimelineItemDTO[];
  isLoading:    boolean;
  selectedItem: AuthAuditTimelineItemDTO | null;
  onSelect:     (item: AuthAuditTimelineItemDTO) => void;
}

export function TimelineRail({
  items,
  isLoading,
  selectedItem,
  onSelect,
}: TimelineRailProps) {
  if (isLoading) {
    return (
      <div className="p-4 space-y-3">
        {Array.from({ length: 8 }).map((_, i) => (
          <div key={i} className="flex items-start gap-3">
            <Skeleton className="mt-1 h-2 w-2 rounded-full shrink-0" />
            <div className="flex-1 space-y-1.5">
              <Skeleton className="h-3 w-32 rounded" />
              <Skeleton className="h-3 w-48 rounded" />
              <Skeleton className="h-3 w-28 rounded" />
            </div>
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
          key={item.id}
          item={item}
          isSelected={selectedItem?.id === item.id}
          onSelect={onSelect}
        />
      ))}
    </div>
  );
}