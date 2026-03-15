"use client";

import { cn } from "@/lib/utils";
import type { AuditLevel } from "../auth_audit.types";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface SecurityStats {
  total:          number;   // totalElements from backend — real count across all pages
  failedAttempts: number;   // page-scoped: success === false
  securityAlerts: number;   // page-scoped: level === CRITICAL or WARN
  successEvents:  number;   // page-scoped: success === true
}

// ─── Config ───────────────────────────────────────────────────────────────────

const STAT_CONFIG = [
  {
    key:       "total"          as const,
    label:     "Total Events",
    tooltip:   "All security audit events matching current filters (from backend)",
    boxClass:  "bg-surface-3        border-gs-line-2       text-t1",
    pulse:     false,
    pageBadge: false,
  },
  {
    key:       "failedAttempts" as const,
    label:     "Failed Attempts",
    tooltip:   "Events where success=false on this page",
    boxClass:  "bg-rose-500/10      border-rose-500/30     text-rose-600",
    pulse:     true,
    pageBadge: true,
  },
  {
    key:       "securityAlerts" as const,
    label:     "Security Alerts",
    tooltip:   "CRITICAL or WARN level events on this page",
    boxClass:  "bg-amber-500/10     border-amber-500/30    text-amber-600",
    pulse:     true,
    pageBadge: true,
  },
  {
    key:       "successEvents"  as const,
    label:     "Successes",
    tooltip:   "Events where success=true on this page",
    boxClass:  "bg-emerald-500/10   border-emerald-500/30  text-emerald-600",
    pulse:     false,
    pageBadge: true,
  },
] as const;

// ─── Component ────────────────────────────────────────────────────────────────

export function StatsStrip({ stats }: { stats: SecurityStats }) {
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
            <div
              className={cn(
                "flex h-8 w-8 shrink-0 items-center justify-center rounded-gs border",
                "text-sm font-bold font-head",
                cfg.boxClass,
                hasPulse && "animate-pulse",
              )}
            >
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

// ─── Helper exported for the page to derive stats ─────────────────────────────

/** Levels that constitute a "Security Alert" on the StatsStrip. */
const ALERT_LEVELS: AuditLevel[] = ["CRITICAL", "WARN"];

export function deriveSecurityStats(
  items: { success: boolean; level: AuditLevel }[],
  totalElements: number
): SecurityStats {
  return {
    total:          totalElements,
    failedAttempts: items.filter((i) => !i.success).length,
    securityAlerts: items.filter((i) => ALERT_LEVELS.includes(i.level)).length,
    successEvents:  items.filter((i) => i.success).length,
  };
}