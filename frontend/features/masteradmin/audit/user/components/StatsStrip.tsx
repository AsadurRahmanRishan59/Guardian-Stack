"use client";

import { cn } from "@/lib/utils";

interface Stats {
  total: number;
  critical: number;
  escalations: number;
  unknown: number;
}

// Semantic mapping:
//   total       → neutral surface  (informational, no alarm)
//   critical    → destructive      (account locked / disabled)
//   escalations → brand-orange     (privilege change — elevated but not broken)
//   unknown     → brand-orange/60  (suspicious but lower severity than critical)
const STAT_CONFIG = [
  {
    key:       "total",
    label:     "Total Events",
    boxClass:  "bg-surface-3      border-gs-line-2    text-t1",
    pulse:     false,
  },
  {
    key:       "critical",
    label:     "Critical Changes",
    boxClass:  "bg-destructive/10 border-destructive/25 text-destructive",
    pulse:     true,
  },
  {
    key:       "escalations",
    label:     "Admin Escalations",
    boxClass:  "bg-brand-soft     border-brand-border   text-brand",
    pulse:     false,
  },
  {
    key:       "unknown",
    label:     "Unknown IPs",
    boxClass:  "bg-brand-soft/60  border-brand-border/60 text-brand/80",
    pulse:     false,
  },
] as const;

export function StatsStrip({ stats }: { stats: Stats }) {
  return (
    <div className="grid grid-cols-2 md:grid-cols-4 border-b border-gs-line bg-surface-2/40 shrink-0">
      {STAT_CONFIG.map((cfg, i) => {
        const value    = stats[cfg.key as keyof Stats];
        const isLast   = i === STAT_CONFIG.length - 1;
        const hasPulse = cfg.pulse && value > 0;

        return (
          <div
            key={cfg.key}
            className={cn(
              "flex items-center gap-3 px-4 md:px-5 py-2.5",
              !isLast   && "border-r border-gs-line",
              i < 2     && "border-b md:border-b-0 border-gs-line",
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
            <span className="text-[11px] font-body text-t3 leading-tight">
              {cfg.label}
            </span>
          </div>
        );
      })}
    </div>
  );
}