"use client";

import { cn } from "@/lib/utils";
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

// ─── REV_CFG ─────────────────────────────────────────────────────────────────

export const REV_CFG = {
  CREATED:  { label: "ADD", icon: "+",  className: "text-green-400 bg-green-400/10 border-green-400/30"  },
  MODIFIED: { label: "MOD", icon: "✎", className: "text-blue-400  bg-blue-400/10  border-blue-400/30"   },
  DELETED:  { label: "DEL", icon: "🗑", className: "text-red-400   bg-red-400/10   border-red-400/30"    },
} as const;

// ─── RevBadge ────────────────────────────────────────────────────────────────

export function RevBadge({ type }: { type: string }) {
  const cfg = REV_CFG[type as keyof typeof REV_CFG] ?? REV_CFG.MODIFIED;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-bold font-mono border tracking-wide",
        cfg.className
      )}
    >
      {cfg.icon} {cfg.label}
    </span>
  );
}

// ─── IPLabel ─────────────────────────────────────────────────────────────────

export function IPLabel({ ip }: { ip: string }) {
  const known = isKnownIP(ip);
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 font-mono text-[11px]",
        known ? "text-muted-foreground" : "text-orange-400"
      )}
    >
      {!known && <AlertTriangle className="h-3 w-3" />}
      {ip}
      {!known && (
        <span className="text-[9px] text-orange-400/50 font-bold tracking-wider">
          EXTERNAL
        </span>
      )}
    </span>
  );
}

// ─── RolePill ────────────────────────────────────────────────────────────────

type RoleVariant = "neutral" | "added" | "removed" | "admin";

const ROLE_STYLES: Record<RoleVariant, string> = {
  neutral: "text-muted-foreground bg-muted/60 border-border",
  added:   "text-green-400 bg-green-400/10 border-green-400/30",
  removed: "text-red-400   bg-red-400/10   border-red-400/25",
  admin:   "text-amber-400 bg-amber-400/10 border-amber-400/35",
};

export function RolePill({ role, variant = "neutral" }: { role: string; variant?: RoleVariant }) {
  return (
    <span
      className={cn(
        "inline-block px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold border mx-0.5 my-0.5",
        ROLE_STYLES[variant]
      )}
    >
      {role.replace("ROLE_", "")}
    </span>
  );
}