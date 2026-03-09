"use client";

import { cn } from "@/lib/utils";
import type { AuditTimelineItemDTO } from "@/features/masteradmin/audit/user/user.types";
import { RevBadge, IPLabel, formatTs } from "./UiPrimitives";
import { Skeleton } from "@/components/ui/skeleton";

// ─── TimelineNode ─────────────────────────────────────────────────────────────

function TimelineNode({
  item,
  isSelected,
  isLastInGroup,
  onClick,
}: {
  item:          AuditTimelineItemDTO;
  isSelected:    boolean;
  isLastInGroup: boolean;
  onClick:       () => void;
}) {
  const { date, time } = formatTs(item.timestamp);
  const isCritical     = item.accountLocked || !item.enabled;

  // Dot: selected → brand, escalation → brand/60, critical → destructive pulse, default → muted
  const dotClass = isSelected
    ? "bg-brand ring-2 ring-brand/30"
    : item.hasAdminRoleEscalation
    ? "bg-brand/60 ring-1 ring-brand/20"
    : isCritical
    ? "bg-destructive ring-1 ring-destructive/30 animate-pulse"
    : "bg-gs-line-2";

  // Card: selected → brand tint, critical → destructive tint, escalation → brand tint, default
  const cardClass = isSelected
    ? "bg-brand/5 border-brand-border"
    : isCritical
    ? "bg-surface-card border-destructive/20 hover:border-destructive/35"
    : item.hasAdminRoleEscalation
    ? "bg-surface-card border-brand-border/30 hover:border-brand-border/60"
    : "bg-surface-card border-gs-line hover:border-gs-line-2 hover:bg-surface-2/40";

  return (
    <div className="relative pl-7 group" onClick={onClick}>
      {!isLastInGroup && (
        <div className="absolute left-[7px] top-5 bottom-0 w-px bg-gradient-to-b from-gs-line to-transparent" />
      )}
      <div className={cn(
        "absolute left-0 top-4 h-3.5 w-3.5 rounded-full transition-all duration-150 z-10",
        dotClass,
      )} />

      <button
        className={cn(
          "w-full text-left mb-1.5 px-3 py-2.5 rounded-gs border transition-all duration-150",
          "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand",
          cardClass,
        )}
      >
        {/* Rev number + type badge + flags */}
        <div className="flex items-center gap-1.5 mb-1.5 flex-wrap">
          <span className="font-head text-xs font-bold text-brand">#{item.revisionNumber}</span>
          <RevBadge type={item.revisionType} />
          {isCritical              && <span title="Critical account change"  className="text-sm leading-none">🚩</span>}
          {item.hasAdminRoleEscalation && <span title="Admin role escalation" className="text-sm leading-none">👑</span>}
        </div>

        {/* Timestamp */}
        <div className="flex items-center gap-1.5 mb-1">
          <span className="font-body text-[11px] text-t3">{date}</span>
          <span className="text-[9px] text-t4">·</span>
          <span className="font-body text-[11px] text-t4">{time}</span>
        </div>

        {/* Actor + IP */}
        <div className="flex items-center gap-1.5 mb-1 flex-wrap">
          <span className="font-body text-[11px] text-t4">by</span>
          <span className="font-body text-xs font-semibold text-t2">{item.changedBy}</span>
          <span className="text-[9px] text-t4">·</span>
          <IPLabel ip={item.ipAddress} />
        </div>

        {/* Email */}
        <div className="font-body text-[10px] text-t4 truncate">{item.email}</div>
      </button>
    </div>
  );
}

// ─── UserGroupHeader ──────────────────────────────────────────────────────────

function UserGroupHeader({ email }: { email: string }) {
  return (
    <div className="mb-2 ml-7 pb-1.5 border-b border-gs-line">
      <span className="text-[9px] font-bold tracking-widest uppercase text-t4">
        User · {email}
      </span>
    </div>
  );
}

// ─── Loading Skeleton ─────────────────────────────────────────────────────────

function TimelineSkeleton() {
  return (
    <div className="flex flex-col gap-2 pt-2 pl-7">
      {Array.from({ length: 8 }).map((_, i) => (
        <Skeleton
          key={i}
          className="h-[88px] w-full rounded-gs bg-surface-2"
          style={{ opacity: 1 - i * 0.1 }}
        />
      ))}
    </div>
  );
}

// ─── Empty State ──────────────────────────────────────────────────────────────

function EmptyState() {
  return (
    <div className="flex flex-col items-center justify-center gap-3 pt-16">
      <span className="text-4xl">📭</span>
      <p className="font-body text-sm text-t3 text-center max-w-[180px] leading-relaxed">
        No audit events match your filters.
      </p>
    </div>
  );
}

// ─── TimelineRail ─────────────────────────────────────────────────────────────

interface TimelineRailProps {
  items:        AuditTimelineItemDTO[];
  isLoading:    boolean;
  selectedItem: AuditTimelineItemDTO | null;
  onSelect:     (item: AuditTimelineItemDTO) => void;
}

export function TimelineRail({ items, isLoading, selectedItem, onSelect }: TimelineRailProps) {
  if (isLoading)        return <div className="p-4 md:p-5"><TimelineSkeleton /></div>;
  if (items.length === 0) return <EmptyState />;

  const nodes: React.ReactNode[] = [];
  let lastUserId: number | null  = null;
  const userHeaderCount          = new Map<number, number>();

  items.forEach((item, i) => {
    if (item.userId !== lastUserId) {
      lastUserId = item.userId;
      const count = (userHeaderCount.get(item.userId) ?? 0) + 1;
      userHeaderCount.set(item.userId, count);
      nodes.push(
        <UserGroupHeader key={`header-${item.userId}-${count}`} email={item.email} />
      );
    }

    const isLastInGroup = i === items.length - 1 || items[i + 1]?.userId !== item.userId;

    nodes.push(
      <TimelineNode
        key={`rev-${item.revisionNumber}`}
        item={item}
        isSelected={selectedItem?.revisionNumber === item.revisionNumber}
        isLastInGroup={isLastInGroup}
        onClick={() => onSelect(item)}
      />
    );
  });

  return <div className="p-4 md:p-5">{nodes}</div>;
}