"use client";

import { cn } from "@/lib/utils";

interface Stats {
  total: number;
  critical: number;
  escalations: number;
  unknown: number;
}

const STAT_CONFIG = [
  { key: "total",       label: "Total Events",       colorClass: "text-blue-400  bg-blue-400/10  border-blue-400/20",   pulse: false },
  { key: "critical",    label: "Critical Changes",    colorClass: "text-red-400   bg-red-400/10   border-red-400/20",    pulse: true  },
  { key: "escalations", label: "Admin Escalations",   colorClass: "text-amber-400 bg-amber-400/10 border-amber-400/20",  pulse: false },
  { key: "unknown",     label: "Unknown IPs",         colorClass: "text-orange-400 bg-orange-400/10 border-orange-400/20", pulse: false },
] as const;

export function StatsStrip({ stats }: { stats: Stats }) {
  return (
    <div className="grid grid-cols-2 md:grid-cols-4 border-b border-border bg-background/40 shrink-0">
      {STAT_CONFIG.map((cfg, i) => {
        const value = stats[cfg.key as keyof Stats];
        const isLast = i === STAT_CONFIG.length - 1;
        const hasPulse = cfg.pulse && value > 0;

        return (
          <div
            key={cfg.key}
            className={cn(
              "flex items-center gap-3 px-4 md:px-5 py-2.5",
              !isLast && "border-r border-border",
              // bottom border on first row for mobile 2-col grid
              i < 2 && "border-b md:border-b-0 border-border"
            )}
          >
            <div
              className={cn(
                "flex h-8 w-8 shrink-0 items-center justify-center rounded-md border text-sm font-bold font-mono",
                cfg.colorClass,
                hasPulse && "animate-pulse"
              )}
            >
              {value}
            </div>
            <span className="text-[11px] text-muted-foreground leading-tight">
              {cfg.label}
            </span>
          </div>
        );
      })}
    </div>
  );
}