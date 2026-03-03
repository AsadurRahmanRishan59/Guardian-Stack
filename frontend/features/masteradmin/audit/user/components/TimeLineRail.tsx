"use client";

import { cn } from "@/lib/utils";
import type { AuditTimelineItemDTO } from "@/features/masteradmin/audit/user/user.types";
import { RevBadge, IPLabel, formatTs, isKnownIP } from "./UiPrimitives";
import { Skeleton } from "@/components/ui/skeleton";
// ─── TimelineNode ─────────────────────────────────────────────────────────────

function TimelineNode({
  item,
  isSelected,
  isLastInGroup,
  onClick,
}: {
  item: AuditTimelineItemDTO;
  isSelected: boolean;
  isLastInGroup: boolean;
  onClick: () => void;
}) {
  const { date, time } = formatTs(item.timestamp);
  const isCritical = item.accountLocked || !item.enabled;

  const dotColor = isSelected
    ? "bg-blue-500 ring-2 ring-blue-500/30"
    : item.hasAdminRoleEscalation
    ? "bg-amber-400 ring-1 ring-amber-400/30"
    : isCritical
    ? "bg-red-500 ring-1 ring-red-500/30 animate-pulse"
    : "bg-muted-foreground/20";

  return (
    <div className="relative pl-7 group" onClick={onClick}>
      {/* Connector line */}
      {!isLastInGroup && (
        <div className="absolute left-1.75 top-5 bottom-0 w-0.5 bg-liner-to-b from-border to-transparent" />
      )}

      {/* Dot */}
      <div
        className={cn(
          "absolute left-0 top-4 h-3.5 w-3.5 rounded-full transition-all duration-150 z-10",
          dotColor
        )}
      />

      {/* Card */}
      <button
        className={cn(
          "w-full text-left mb-1.5 px-3 py-2.5 rounded-lg border transition-all duration-150",
          "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500",
          isSelected
            ? "bg-blue-500/5 border-blue-500/30"
            : isCritical
            ? "bg-background border-red-500/15 hover:border-red-500/30"
            : item.hasAdminRoleEscalation
            ? "bg-background border-amber-400/15 hover:border-amber-400/30"
            : "bg-card border-border hover:border-border/80 hover:bg-accent/30"
        )}
      >
        {/* Row 1: revision # + badge + flags */}
        <div className="flex items-center gap-1.5 mb-1.5 flex-wrap">
          <span className="font-mono text-xs font-bold text-blue-400">
            #{item.revisionNumber}
          </span>
          <RevBadge type={item.revisionType} />
          {isCritical && <span title="Critical account change" className="text-sm">🚩</span>}
          {item.hasAdminRoleEscalation && <span title="Admin role escalation" className="text-sm">👑</span>}
        </div>

        {/* Row 2: date + time */}
        <div className="flex items-center gap-1.5 mb-1">
          <span className="text-[11px] text-muted-foreground/60">{date}</span>
          <span className="text-[9px] text-muted-foreground/20">·</span>
          <span className="font-mono text-[11px] text-muted-foreground/50">{time}</span>
        </div>

        {/* Row 3: actor + IP */}
        <div className="flex items-center gap-1.5 mb-1 flex-wrap">
          <span className="text-[11px] text-muted-foreground/50">by</span>
          <span className="text-xs font-semibold text-foreground/80">{item.changedBy}</span>
          <span className="text-[9px] text-muted-foreground/20">·</span>
          <IPLabel ip={item.ipAddress} />
        </div>

        {/* Row 4: email */}
        <div className="font-mono text-[10px] text-muted-foreground/35 truncate">
          {item.email}
        </div>
      </button>
    </div>
  );
}

// ─── UserGroupHeader ──────────────────────────────────────────────────────────

function UserGroupHeader({ email }: { email: string }) {
  return (
    <div className="mb-2 ml-7 pb-1.5 border-b border-border/50">
      <span className="text-[9px] font-bold tracking-widest uppercase text-muted-foreground/30">
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
          className="h-22 w-full rounded-lg"
          style={{ opacity: 1 - i * 0.1 }}
        />
      ))}
    </div>
  );
}

// ─── Empty State ─────────────────────────────────────────────────────────────

function EmptyState() {
  return (
    <div className="flex flex-col items-center justify-center gap-3 pt-16">
      <span className="text-4xl">📭</span>
      <p className="text-sm text-muted-foreground text-center max-w-45">
        No audit events match your filters.
      </p>
    </div>
  );
}

// ─── TimelineRail ─────────────────────────────────────────────────────────────

interface TimelineRailProps {
  items: AuditTimelineItemDTO[];
  isLoading: boolean;
  selectedItem: AuditTimelineItemDTO | null;
  onSelect: (item: AuditTimelineItemDTO) => void;
}

export function TimelineRail({ items, isLoading, selectedItem, onSelect }: TimelineRailProps) {
  if (isLoading) return <div className="p-4 md:p-5"><TimelineSkeleton /></div>;
  if (items.length === 0) return <EmptyState />;

  // Group by userId
  const nodes: React.ReactNode[] = [];
  let lastUserId: number | null = null;

  items.forEach((item, i) => {
    if (item.userId !== lastUserId) {
      lastUserId = item.userId;
      nodes.push(<UserGroupHeader key={`header-${item.userId}`} email={item.email} />);
    }
    const isLastInGroup =
      i === items.length - 1 || items[i + 1]?.userId !== item.userId;

    nodes.push(
      <TimelineNode
        key={item.revisionNumber}
        item={item}
        isSelected={selectedItem?.revisionNumber === item.revisionNumber}
        isLastInGroup={isLastInGroup}
        onClick={() => onSelect(item)}
      />
    );
  });

  return (
    <div className="p-4 md:p-5">
      {nodes}
    </div>
  );
}