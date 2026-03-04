"use client";

// ─────────────────────────────────────────────────────────────────────────────
// FilterBar — debounced text + date inputs, instant rev-type toggles
//
// Why no "setState in effect" error here:
//   The effects below call onUpdate() which is the PARENT's state setter,
//   not this component's setState. The lint rule only fires when you call
//   your own component's setState inside an effect, because that causes
//   this component to re-render cascadingly.
//
// Why no sync-back effect:
//   FilterInputs is fully uncontrolled. When the user clicks "Clear", the
//   parent increments resetKey which remounts <FilterInputs />, resetting
//   all local state to EMPTY without any setState-in-effect.
// ─────────────────────────────────────────────────────────────────────────────

import { useState, useEffect, useCallback } from "react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { X, ChevronLeft, ChevronRight, CalendarIcon } from "lucide-react";
import { cn } from "@/lib/utils";

import type { AuditFilterRequest } from "@/features/masteradmin/audit/user/user.types";
import { useDebounce } from "@/lib/hooks/useDebounce";

// ─── Config ───────────────────────────────────────────────────────────────────

const REV_CFG = {
  CREATED:  { label: "ADD", icon: "+",  activeClass: "border-green-500 bg-green-500/10 text-green-400",  inactiveClass: "border-border text-muted-foreground" },
  MODIFIED: { label: "MOD", icon: "✎", activeClass: "border-blue-500  bg-blue-500/10  text-blue-400",   inactiveClass: "border-border text-muted-foreground" },
  DELETED:  { label: "DEL", icon: "🗑", activeClass: "border-red-500   bg-red-500/10   text-red-400",    inactiveClass: "border-border text-muted-foreground" },
} as const;

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** "2026-03-01T00:00" → "2026-03-01T00:00:00" for Spring */
function toIso(v: string): string | undefined {
  if (!v) return undefined;
  return v.length === 16 ? `${v}:00` : v;
}

// ─── Local state shape ────────────────────────────────────────────────────────

interface LocalFilters {
  email: string; changedBy: string; ipAddress: string;
  from:  string; to:        string;
}
const EMPTY: LocalFilters = { email: "", changedBy: "", ipAddress: "", from: "", to: "" };

// ─── Props ────────────────────────────────────────────────────────────────────

interface FilterBarProps {
  filter:           AuditFilterRequest;
  onUpdate:         (patch: Partial<AuditFilterRequest>) => void;
  onClear:          () => void;
  hasActiveFilters: boolean;
  totalElements:    number;
  totalPages:       number;
  onPageChange:     (page: number) => void;
}

// ─── FilterInputs — fully uncontrolled, remounted on clear ───────────────────

function FilterInputs({
  onUpdate,
  onPendingChange,
}: {
  onUpdate:        (patch: Partial<AuditFilterRequest>) => void;
  onPendingChange: (pending: boolean) => void;
}) {
  const [local, setLocal] = useState<LocalFilters>(EMPTY);
  const set = useCallback((key: keyof LocalFilters, value: string) => {
    setLocal((prev) => ({ ...prev, [key]: value }));
  }, []);

  // Debounced values — only these propagate to the API
  const dEmail     = useDebounce(local.email,     400);
  const dChangedBy = useDebounce(local.changedBy, 400);
  const dIpAddress = useDebounce(local.ipAddress, 400);
  const dFrom      = useDebounce(local.from,      600);
  const dTo        = useDebounce(local.to,        600);

  // ✅ Calling onUpdate (parent's setter) inside useEffect is correct.
  //    This does NOT call setLocal, so it cannot cause cascading re-renders
  //    on this component. The lint error only applies to your own setState.
  useEffect(() => { onUpdate({ email:     dEmail     || undefined }); }, [dEmail]);     // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { onUpdate({ changedBy: dChangedBy || undefined }); }, [dChangedBy]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { onUpdate({ ipAddress: dIpAddress || undefined }); }, [dIpAddress]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { onUpdate({ from:      toIso(dFrom) });             }, [dFrom]);     // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { onUpdate({ to:        toIso(dTo) });               }, [dTo]);       // eslint-disable-line react-hooks/exhaustive-deps

  // Inform parent whether a debounce is in flight (drives Clear button visibility)
  const isPending =
    local.email !== dEmail || local.changedBy !== dChangedBy ||
    local.ipAddress !== dIpAddress || local.from !== dFrom || local.to !== dTo;

  useEffect(() => { onPendingChange(isPending); }, [isPending, onPendingChange]);

  // Quick date preset — fires immediately, no need to wait for debounce
  const applyPreset = (days: number) => {
    const now   = new Date();
    const start = new Date(now);
    start.setDate(start.getDate() - days);
    start.setHours(0, 0, 0, 0);
    const toStr   = now.toISOString().slice(0, 16);
    const fromStr = days === 0
      ? now.toISOString().slice(0, 10) + "T00:00"
      : start.toISOString().slice(0, 16);
    setLocal((prev) => ({ ...prev, from: fromStr, to: toStr }));
    onUpdate({ from: toIso(fromStr), to: toIso(toStr) });
  };

  const clearDates = () => {
    setLocal((prev) => ({ ...prev, from: "", to: "" }));
    onUpdate({ from: undefined, to: undefined });
  };

  return (
    <div className="flex flex-col gap-2">

      {/* ── Row 1: text inputs ── */}
      <div className="flex flex-wrap gap-2">
        {([
          { key: "email"     as const, debounced: dEmail,     placeholder: "Email / User ID",   className: "w-44" },
          { key: "changedBy" as const, debounced: dChangedBy, placeholder: "Actor (changedBy)", className: "w-40" },
          { key: "ipAddress" as const, debounced: dIpAddress, placeholder: "IP or prefix",      className: "w-32" },
        ]).map(({ key, debounced, placeholder, className }) => (
          <div key={key} className="relative">
            <Input
              value={local[key]}
              onChange={(e) => set(key, e.target.value)}
              placeholder={placeholder}
              className={cn(
                "h-7 text-xs font-mono bg-muted/40 border-border",
                "placeholder:text-muted-foreground/25",
                "focus-visible:ring-1 focus-visible:ring-blue-500",
                local[key] !== debounced && "border-blue-500/30",
                className
              )}
            />
            {local[key] !== debounced && (
              <span className="absolute right-1.5 top-1/2 -translate-y-1/2 h-1.5 w-1.5 rounded-full bg-blue-400 animate-pulse" />
            )}
          </div>
        ))}
      </div>

      {/* ── Row 2: date range ── */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="hidden sm:flex items-center gap-1 text-[9px] font-bold tracking-widest uppercase text-muted-foreground/40">
          <CalendarIcon className="h-2.5 w-2.5" /> Date range
        </span>

        {([
          { key: "from" as const, debounced: dFrom, label: "from" },
          { key: "to"   as const, debounced: dTo,   label: "to"   },
        ]).map(({ key, debounced, label }, i) => (
          <div key={key} className="flex items-center gap-1.5">
            {i === 1 && <span className="hidden sm:block text-muted-foreground/25 text-xs">→</span>}
            <span className="hidden xs:block text-[10px] text-muted-foreground/40 font-mono">{label}</span>
            <div className="relative">
              <Input
                type="datetime-local"
                value={local[key]}
                onChange={(e) => set(key, e.target.value)}
                className={cn(
                  "h-7 w-48 text-xs font-mono bg-muted/40 border-border pr-2 [color-scheme:dark]",
                  "focus-visible:ring-1 focus-visible:ring-blue-500",
                  local[key] !== debounced && "border-blue-500/30"
                )}
              />
              {local[key] !== debounced && (
                <span className="absolute right-1.5 top-1/2 -translate-y-1/2 h-1.5 w-1.5 rounded-full bg-blue-400 animate-pulse" />
              )}
            </div>
          </div>
        ))}

        {/* Quick presets */}
        <div className="flex gap-1">
          {[{ label: "Today", days: 0 }, { label: "7d", days: 7 }, { label: "30d", days: 30 }].map(
            ({ label, days }) => (
              <button
                key={label}
                onClick={() => applyPreset(days)}
                className="h-6 px-2 rounded border border-border text-[10px] font-mono text-muted-foreground/50 hover:text-muted-foreground hover:border-muted-foreground/30 transition-all"
              >
                {label}
              </button>
            )
          )}
          {(local.from || local.to) && (
            <button
              onClick={clearDates}
              title="Clear date range"
              className="h-6 px-1.5 rounded border border-border text-muted-foreground/30 hover:text-red-400 hover:border-red-400/30 transition-all"
            >
              <X className="h-2.5 w-2.5" />
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── FilterBar ────────────────────────────────────────────────────────────────

export function FilterBar({
  filter,
  onUpdate,
  onClear,
  hasActiveFilters,
  totalElements,
  totalPages,
  onPageChange,
}: FilterBarProps) {
  const [resetKey,   setResetKey]   = useState(0);
  const [isPending,  setIsPending]  = useState(false);

  const handleClear = () => {
    setResetKey((k) => k + 1); // remounts FilterInputs → all local state resets to EMPTY
    onClear();
  };

  const toggleRevType = (type: string) => {
    const active = filter.revisionTypes?.split(",").filter(Boolean) ?? [];
    const next = active.includes(type)
      ? active.filter((t) => t !== type)
      : [...active, type];
    onUpdate({ revisionTypes: next.join(",") || undefined });
  };

  const currentPage    = filter.page ?? 0;
  const activeRevTypes = filter.revisionTypes?.split(",").filter(Boolean) ?? [];

  return (
    <div className="flex flex-col gap-2 px-4 md:px-6 py-2.5 border-b border-border bg-background/60 shrink-0">
      <div className="flex flex-wrap items-start gap-2">

        <span className="text-[9px] font-bold tracking-widest uppercase text-muted-foreground/40 mt-2 hidden sm:block">
          Filter
        </span>

        {/* Remountable inputs — key increment resets all local state cleanly */}
        <div className="flex-1 min-w-0">
          <FilterInputs
            key={resetKey}
            onUpdate={onUpdate}
            onPendingChange={setIsPending}
          />
        </div>

        {/* Rev-type toggles */}
        <div className="flex flex-wrap gap-1.5">
          {(["CREATED", "MODIFIED", "DELETED"] as const).map((type) => {
            const cfg    = REV_CFG[type];
            const active = activeRevTypes.includes(type);
            return (
              <button
                key={type}
                onClick={() => toggleRevType(type)}
                className={cn(
                  "h-7 px-2.5 rounded-md border text-[10px] font-bold font-mono tracking-wide transition-all duration-100 hover:opacity-80",
                  active ? cfg.activeClass : cfg.inactiveClass
                )}
              >
                {cfg.icon} {type}
              </button>
            );
          })}
        </div>

        {/* Clear all */}
        {(hasActiveFilters || isPending) && (
          <Button
            variant="ghost"
            size="sm"
            onClick={handleClear}
            className="h-7 px-2 text-xs text-muted-foreground hover:text-foreground"
          >
            <X className="h-3 w-3 mr-1" />
            Clear
          </Button>
        )}

        {/* Event count + pagination */}
        <div className="flex items-center gap-3 ml-auto">
          <Badge variant="secondary" className="text-[10px] font-mono font-normal hidden sm:flex">
            {totalElements.toLocaleString()} events
          </Badge>

          {totalPages > 1 && (
            <div className="flex items-center gap-1">
              <Button variant="outline" size="icon" className="h-6 w-6"
                onClick={() => onPageChange(currentPage - 1)} disabled={currentPage === 0}>
                <ChevronLeft className="h-3 w-3" />
              </Button>
              <span className="text-[10px] font-mono text-muted-foreground min-w-[48px] text-center">
                {currentPage + 1} / {totalPages}
              </span>
              <Button variant="outline" size="icon" className="h-6 w-6"
                onClick={() => onPageChange(currentPage + 1)} disabled={currentPage >= totalPages - 1}>
                <ChevronRight className="h-3 w-3" />
              </Button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}