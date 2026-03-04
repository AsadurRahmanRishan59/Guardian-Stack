"use client";

import { cn } from "@/lib/utils";
import { AppRole } from "@/types/auth.types";
import { AlertTriangle } from "lucide-react";


// ─── Helpers ─────────────────────────────────────────────────────────────────

const TRUSTED_IP_PREFIXES = ["192.168.", "10.0.", "172.16."];

export function isKnownIP(ip: string) {
  return TRUSTED_IP_PREFIXES.some((p) => ip?.startsWith(p));
}

export function formatTs(iso: string) {
  if (!iso) return { date: "—", time: "—" };
  const d = new Date(iso);
  return {
    date: d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" }),
    time: d.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
  };
}

// ─── RevBadge ────────────────────────────────────────────────────────────────

export const REV_CFG = {
  CREATED:  { label: "ADD", icon: "+",  className: "text-green-400 bg-green-400/10 border-green-400/30" },
  MODIFIED: { label: "MOD", icon: "✎", className: "text-blue-400  bg-blue-400/10  border-blue-400/30"  },
  DELETED:  { label: "DEL", icon: "🗑", className: "text-red-400   bg-red-400/10   border-red-400/30"   },
} as const;

export function RevBadge({ type }: { type: string }) {
  const cfg = REV_CFG[type as keyof typeof REV_CFG] ?? REV_CFG.MODIFIED;
  return (
    <span className={cn(
      "inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-bold font-mono border tracking-wide",
      cfg.className
    )}>
      {cfg.icon} {cfg.label}
    </span>
  );
}

// ─── IPLabel ─────────────────────────────────────────────────────────────────

export function IPLabel({ ip }: { ip: string }) {
  const known = isKnownIP(ip);
  return (
    <span className={cn(
      "inline-flex items-center gap-1 font-mono text-[11px]",
      known ? "text-muted-foreground" : "text-orange-400"
    )}>
      {!known && <AlertTriangle className="h-3 w-3" />}
      {ip}
      {!known && <span className="text-[9px] text-orange-400/50 font-bold tracking-wider">EXTERNAL</span>}
    </span>
  );
}

// ─── RolePill ────────────────────────────────────────────────────────────────
//
// Variant map aligned with AppRole enum:
//   ROLE_MASTER_ADMIN → "master"   red/rose  (highest privilege, most critical)
//   ROLE_ADMIN        → "admin"    amber     (elevated privilege)
//   ROLE_EMPLOYEE     → "employee" blue      (internal staff)
//   ROLE_USER         → "user"     slate     (standard user)
//   fallback          → "neutral"  muted

export type RoleVariant = "neutral" | "added" | "removed" | "master" | "admin" | "employee" | "user";

const ROLE_STYLES: Record<RoleVariant, string> = {
  neutral:  "text-muted-foreground  bg-muted/60         border-border",
  added:    "text-green-400         bg-green-400/10     border-green-400/30",
  removed:  "text-red-400           bg-red-400/10       border-red-400/25",
  master:   "text-rose-400          bg-rose-400/10      border-rose-400/35",
  admin:    "text-amber-400         bg-amber-400/10     border-amber-400/35",
  employee: "text-blue-400          bg-blue-400/10      border-blue-400/30",
  user:     "text-slate-400         bg-slate-400/10     border-slate-400/25",
};

/** Derive the display variant from the raw role string. */
export function getRoleVariant(role: string): RoleVariant {
  switch (role) {
    case AppRole.MASTER_ADMIN: return "master";
    case AppRole.ADMIN:        return "admin";
    case AppRole.EMPLOYEE:     return "employee";
    case AppRole.USER:         return "user";
    default:                   return "neutral";
  }
}

export function RolePill({
  role,
  variant,
}: {
  role: string;
  /** If omitted, variant is derived automatically from the role string. */
  variant?: RoleVariant;
}) {
  const resolvedVariant = variant ?? getRoleVariant(role);
  return (
    <span className={cn(
      "inline-block px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold border mx-0.5 my-0.5",
      ROLE_STYLES[resolvedVariant]
    )}>
      {role.replace("ROLE_", "")}
    </span>
  );
}