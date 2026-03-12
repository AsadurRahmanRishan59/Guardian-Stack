"use client";

import { cn } from "@/lib/utils";

interface Stats {
  total:       number;   // from backend totalElements — real count
  critical:    number;   // page-scoped: locked/disabled accounts
  escalations: number;   // page-scoped: admin role granted
  unknown:     number;   // page-scoped: unrecognised IPs
}

const STAT_CONFIG = [
  {
    key:       "total"       as const,
    label:     "Total Events",
    tooltip:   "All revisions matching current filters (from backend)",
    boxClass:  "bg-surface-3      border-gs-line-2      text-t1",
    pulse:     false,
    pageBadge: false,
  },
  {
    key:       "critical"    as const,
    label:     "Critical",
    tooltip:   "Locked or disabled accounts on this page",
    boxClass:  "bg-destructive/10 border-destructive/25  text-destructive",
    pulse:     true,
    pageBadge: true,
  },
  {
    key:       "escalations" as const,
    label:     "Escalations",
    tooltip:   "Admin role granted on this page",
    boxClass:  "bg-brand-soft     border-brand-border    text-brand",
    pulse:     false,
    pageBadge: true,
  },
  {
    key:       "unknown"     as const,
    label:     "Unknown IPs",
    tooltip:   "Unrecognised IP addresses on this page",
    boxClass:  "bg-brand-soft/60  border-brand-border/60 text-brand/80",
    pulse:     false,
    pageBadge: true,
  },
] as const;

export function StatsStrip({ stats }: { stats: Stats }) {
  return (
    <div className="grid grid-cols-2 md:grid-cols-4 border-b border-gs-line bg-surface-2/40 shrink-0">
      {STAT_CONFIG.map((cfg, i) => {
        const value    = stats[cfg.key];
        const isLast   = i === STAT_CONFIG.length - 1;
        const hasPulse = cfg.pulse && value > 0;

        return (
          <div
            key={cfg.key}
            title={cfg.tooltip}
            className={cn(
              "flex items-center gap-3 px-4 md:px-5 py-2.5",
              !isLast && "border-r border-gs-line",
              i < 2   && "border-b md:border-b-0 border-gs-line",
            )}
          >
            <div className={cn(
              "flex h-8 w-8 shrink-0 items-center justify-center rounded-gs border",
              "text-sm font-bold font-head",
              cfg.boxClass,
              hasPulse && "animate-pulse",
            )}>
              {value}
            </div>
            <div className="flex flex-col leading-tight">
              <span className="text-[11px] font-body text-t3">{cfg.label}</span>
              {cfg.pageBadge && (
                <span className="text-[9px] font-body text-t4 tracking-wide">this page</span>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}