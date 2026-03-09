"use client";

import { useState, useEffect, useCallback } from "react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { X, ChevronLeft, ChevronRight, CalendarIcon } from "lucide-react";
import { cn } from "@/lib/utils";
import type { AuditFilterRequest } from "@/features/masteradmin/audit/user/user.types";
import { useDebounce } from "@/lib/hooks/useDebounce";

// ─── Rev-type config ──────────────────────────────────────────────────────────

const REV_CFG = {
  CREATED:  {
    icon:          "+",
    activeClass:   "border-gs-green/40    bg-gs-green-bg    text-gs-green",
    inactiveClass: "border-gs-line        text-t4           hover:border-gs-line-2 hover:text-t3",
  },
  MODIFIED: {
    icon:          "✎",
    activeClass:   "border-brand-border   bg-brand-soft     text-brand",
    inactiveClass: "border-gs-line        text-t4           hover:border-gs-line-2 hover:text-t3",
  },
  DELETED:  {
    icon:          "✕",
    activeClass:   "border-destructive/30 bg-destructive/10 text-destructive",
    inactiveClass: "border-gs-line        text-t4           hover:border-gs-line-2 hover:text-t3",
  },
} as const;

// ─── Helpers ──────────────────────────────────────────────────────────────────

function toIso(v: string): string | undefined {
  if (!v) return undefined;
  return v.length === 16 ? `${v}:00` : v;
}

interface LocalFilters {
  email: string; changedBy: string; ipAddress: string;
  from:  string; to:        string;
}
const EMPTY: LocalFilters = { email: "", changedBy: "", ipAddress: "", from: "", to: "" };

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

  const dEmail     = useDebounce(local.email,     400);
  const dChangedBy = useDebounce(local.changedBy, 400);
  const dIpAddress = useDebounce(local.ipAddress, 400);
  const dFrom      = useDebounce(local.from,      600);
  const dTo        = useDebounce(local.to,        600);

  useEffect(() => { onUpdate({ email:     dEmail     || undefined }); }, [dEmail]);     // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { onUpdate({ changedBy: dChangedBy || undefined }); }, [dChangedBy]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { onUpdate({ ipAddress: dIpAddress || undefined }); }, [dIpAddress]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { onUpdate({ from:      toIso(dFrom) });             }, [dFrom]);     // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { onUpdate({ to:        toIso(dTo) });               }, [dTo]);       // eslint-disable-line react-hooks/exhaustive-deps

  const isPending =
    local.email !== dEmail || local.changedBy !== dChangedBy ||
    local.ipAddress !== dIpAddress || local.from !== dFrom || local.to !== dTo;

  useEffect(() => { onPendingChange(isPending); }, [isPending, onPendingChange]);

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

  const inputBase = cn(
    "h-7 text-xs font-body bg-surface border-gs-line text-t1",
    "placeholder:text-t4",
    "focus-visible:ring-1 focus-visible:ring-brand focus-visible:border-brand",
  );

  return (
    <div className="flex flex-col gap-2">

      {/* Row 1: text inputs */}
      <div className="flex flex-wrap gap-2">
        {([
          { key: "email"     as const, debounced: dEmail,     placeholder: "Email / User ID",   width: "w-44" },
          { key: "changedBy" as const, debounced: dChangedBy, placeholder: "Actor (changedBy)", width: "w-40" },
          { key: "ipAddress" as const, debounced: dIpAddress, placeholder: "IP or prefix",      width: "w-32" },
        ]).map(({ key, debounced, placeholder, width }) => (
          <div key={key} className="relative">
            <Input
              value={local[key]}
              onChange={(e) => set(key, e.target.value)}
              placeholder={placeholder}
              className={cn(
                inputBase,
                local[key] !== debounced && "border-brand/40",
                width,
              )}
            />
            {local[key] !== debounced && (
              <span className="absolute right-1.5 top-1/2 -translate-y-1/2 h-1.5 w-1.5 rounded-full bg-brand animate-pulse" />
            )}
          </div>
        ))}
      </div>

      {/* Row 2: date range */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="hidden sm:flex items-center gap-1 text-[9px] font-bold tracking-widest uppercase text-t4">
          <CalendarIcon className="h-2.5 w-2.5" /> Date range
        </span>

        {([
          { key: "from" as const, debounced: dFrom, label: "from" },
          { key: "to"   as const, debounced: dTo,   label: "to"   },
        ]).map(({ key, debounced, label }, i) => (
          <div key={key} className="flex items-center gap-1.5">
            {i === 1 && <span className="hidden sm:block text-t4 text-xs">→</span>}
            <span className="hidden xs:block text-[10px] font-body text-t4">{label}</span>
            <div className="relative">
              <Input
                type="datetime-local"
                value={local[key]}
                onChange={(e) => set(key, e.target.value)}
                className={cn(
                  inputBase,
                  "w-48 pr-2 [color-scheme:light] dark:[color-scheme:dark]",
                  local[key] !== debounced && "border-brand/40",
                )}
              />
              {local[key] !== debounced && (
                <span className="absolute right-1.5 top-1/2 -translate-y-1/2 h-1.5 w-1.5 rounded-full bg-brand animate-pulse" />
              )}
            </div>
          </div>
        ))}

        {/* Quick presets */}
        <div className="flex gap-1">
          {[{ label: "Today", days: 0 }, { label: "7d", days: 7 }, { label: "30d", days: 30 }].map(({ label, days }) => (
            <button
              key={label}
              onClick={() => applyPreset(days)}
              className="h-6 px-2 rounded-gs-sm border border-gs-line text-[10px] font-body text-t4 hover:text-t2 hover:border-gs-line-2 transition-colors"
            >
              {label}
            </button>
          ))}
          {(local.from || local.to) && (
            <button
              onClick={clearDates}
              title="Clear date range"
              className="h-6 px-1.5 rounded-gs-sm border border-gs-line text-t4 hover:text-destructive hover:border-destructive/30 transition-colors"
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

interface FilterBarProps {
  filter:           AuditFilterRequest;
  onUpdate:         (patch: Partial<AuditFilterRequest>) => void;
  onClear:          () => void;
  hasActiveFilters: boolean;
  totalElements:    number;
  totalPages:       number;
  onPageChange:     (page: number) => void;
}

export function FilterBar({
  filter,
  onUpdate,
  onClear,
  hasActiveFilters,
  totalElements,
  totalPages,
  onPageChange,
}: FilterBarProps) {
  const [resetKey,  setResetKey]  = useState(0);
  const [isPending, setIsPending] = useState(false);

  const handleClear = () => {
    setResetKey((k) => k + 1);
    onClear();
  };

  const toggleRevType = (type: string) => {
    const active = filter.revisionTypes?.split(",").filter(Boolean) ?? [];
    const next   = active.includes(type)
      ? active.filter((t) => t !== type)
      : [...active, type];
    onUpdate({ revisionTypes: next.join(",") || undefined });
  };

  const currentPage    = filter.page ?? 0;
  const activeRevTypes = filter.revisionTypes?.split(",").filter(Boolean) ?? [];

  return (
    <div className="flex flex-col gap-2 px-4 md:px-5 py-2.5 border-b border-gs-line bg-surface-card shrink-0">
      <div className="flex flex-wrap items-start gap-2">

        <span className="text-[9px] font-bold tracking-widest uppercase text-t4 mt-2 hidden sm:block">
          Filter
        </span>

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
                  "h-7 px-2.5 rounded-gs-sm border text-[10px] font-bold font-body tracking-wide transition-colors",
                  active ? cfg.activeClass : cfg.inactiveClass,
                )}
              >
                {cfg.icon} {type}
              </button>
            );
          })}
        </div>

        {/* Clear */}
        {(hasActiveFilters || isPending) && (
          <Button
            variant="ghost"
            size="sm"
            onClick={handleClear}
            className="h-7 px-2 text-xs font-body text-t3 hover:text-t1 hover:bg-surface-2"
          >
            <X className="h-3 w-3 mr-1" />
            Clear
          </Button>
        )}

        {/* Count + pagination */}
        <div className="flex items-center gap-3 ml-auto">
          <span className="hidden sm:inline-flex items-center h-5 px-2 rounded-full bg-surface-3 border border-gs-line text-[10px] font-body text-t3">
            {totalElements.toLocaleString()} events
          </span>

          {totalPages > 1 && (
            <div className="flex items-center gap-1">
              <Button
                variant="outline"
                size="icon"
                className="h-6 w-6 border-gs-line text-t3 hover:text-t1 hover:bg-surface-2"
                onClick={() => onPageChange(currentPage - 1)}
                disabled={currentPage === 0}
              >
                <ChevronLeft className="h-3 w-3" />
              </Button>
              <span className="text-[10px] font-body text-t3 min-w-[48px] text-center">
                {currentPage + 1} / {totalPages}
              </span>
              <Button
                variant="outline"
                size="icon"
                className="h-6 w-6 border-gs-line text-t3 hover:text-t1 hover:bg-surface-2"
                onClick={() => onPageChange(currentPage + 1)}
                disabled={currentPage >= totalPages - 1}
              >
                <ChevronRight className="h-3 w-3" />
              </Button>
            </div>
          )}
        </div>

      </div>
    </div>
  );
}