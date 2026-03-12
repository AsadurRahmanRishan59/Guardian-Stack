"use client";

import { useState, useEffect, useCallback } from "react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from "@/components/ui/select";
import {
  X, ChevronLeft, ChevronRight, CalendarIcon,
  Loader2, ChevronDown, ChevronUp, Search,
} from "lucide-react";
import { cn } from "@/lib/utils";
import type { MotorTariffAuditFilterRequest } from "@/features/masteradmin/audit/motortariff/motortariff_audit_types";
import { useDebounce } from "@/lib/hooks/useDebounce";
import { useMotorHierarchy, useMotorTariffs } from "@/features/masteradmin/tariff/motor/motor.tariff.react-query";

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

// ─── Shared Select styles (mirrors MotorTariffFilterForm) ─────────────────────

const triggerCls =
  "h-8 text-xs bg-surface border-gs-line text-t1 w-full overflow-hidden font-body " +
  "focus-visible:ring-brand disabled:opacity-40 " +
  "[&>span]:truncate [&>span]:block [&>span]:overflow-hidden [&>span]:max-w-full";

const contentCls = "w-[var(--radix-select-trigger-width)] min-w-[160px] max-w-[400px]";
const itemCls    =
  "whitespace-normal leading-snug py-2 min-h-[2.5rem] " +
  "flex items-center justify-start text-left cursor-pointer text-xs font-body";
const labelCls   = "font-body text-[9px] font-bold tracking-widest uppercase text-t4 mb-1 block";

function toIso(v: string): string | undefined {
  if (!v) return undefined;
  return v.length === 16 ? `${v}:00` : v;
}

// ─── TariffLookup ─────────────────────────────────────────────────────────────
//
// 4-level cascading dropdowns (Type → Group → Vehicle → Category).
// When all 4 are selected the resolved tariffKey is surfaced via callback,
// locking the audit filter to that single tariff's full lifecycle.

interface TariffLookupProps {
  onTariffResolved:   (tariffKey: number, label: string) => void;
  onTariffCleared:    () => void;
  resolvedTariffKey?: number;
}

function TariffLookup({ onTariffResolved, onTariffCleared, resolvedTariffKey }: TariffLookupProps) {
  const [tariffType,     setTariffType]     = useState<string | undefined>();
  const [groupOfVehicle, setGroupOfVehicle] = useState<string | undefined>();
  const [typeOfVehicle,  setTypeOfVehicle]  = useState<string | undefined>();
  const [category,       setCategory]       = useState<string | undefined>();

  // ── Hierarchy data (same hook as MotorTariffFilterForm) ──────────────────────
  const { options: tariffTypes,   isLoading: loadingTypes  } = useMotorHierarchy("tariffType",     {});
  const { options: vehicleGroups, isLoading: loadingGroups } = useMotorHierarchy("groupOfVehicle", { tariffType });
  const { options: vehicleTypes,  isLoading: loadingVTypes } = useMotorHierarchy("typeOfVehicle",  { tariffType, groupOfVehicle });
  const { options: categories,    isLoading: loadingCats   } = useMotorHierarchy("category",       { tariffType, groupOfVehicle, typeOfVehicle });

  // ── Resolve tariffKey once all 4 levels are chosen ───────────────────────────
  const allSelected = !!(tariffType && groupOfVehicle && typeOfVehicle && category);

  const { motorTariffs, isLoading: resolving } = useMotorTariffs(
    allSelected
      ? { tariffType: tariffType as any, groupOfVehicle, typeOfVehicle, category, size: 1 }
      : undefined
  );

  useEffect(() => {
    if (!allSelected || resolving) return;
    const match = motorTariffs?.[0];
    if (match) {
      onTariffResolved(
        match.tariffKey,
        `${tariffType} · ${groupOfVehicle} · ${typeOfVehicle} · ${category}`
      );
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [motorTariffs, resolving, allSelected]);

  // ── Cascade reset helpers ────────────────────────────────────────────────────
  const handleTariffType = (v: string) => {
    setTariffType(v === "all" ? undefined : v);
    setGroupOfVehicle(undefined);
    setTypeOfVehicle(undefined);
    setCategory(undefined);
    onTariffCleared();
  };
  const handleGroup = (v: string) => {
    setGroupOfVehicle(v === "all" ? undefined : v);
    setTypeOfVehicle(undefined);
    setCategory(undefined);
    onTariffCleared();
  };
  const handleVehicleType = (v: string) => {
    setTypeOfVehicle(v === "all" ? undefined : v);
    setCategory(undefined);
    onTariffCleared();
  };
  const handleCategory = (v: string) => {
    setCategory(v === "all" ? undefined : v);
    onTariffCleared();
  };

  const isResolved = !!resolvedTariffKey;

  return (
    <div className="space-y-2.5">

      {/* Resolved / lifecycle badge */}
      {isResolved && (
        <div className="flex items-center gap-2 px-2.5 py-1.5 rounded-gs border border-brand/30 bg-brand-soft">
          <span className="h-1.5 w-1.5 rounded-full bg-brand shrink-0 animate-pulse" />
          <span className="font-body text-[11px] text-brand font-semibold flex-1 truncate">
            Lifecycle view locked · Tariff #{resolvedTariffKey}
          </span>
          {resolving && <Loader2 className="h-3 w-3 animate-spin text-brand shrink-0" />}
        </div>
      )}

      {/* 4 cascading dropdowns */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-2">

        <div>
          <label className={labelCls}>Tariff Type</label>
          <Select onValueChange={handleTariffType} value={tariffType ?? "all"}>
            <SelectTrigger className={triggerCls}>
              {loadingTypes
                ? <Loader2 className="w-3 h-3 animate-spin" />
                : <SelectValue placeholder="All" />}
            </SelectTrigger>
            <SelectContent className={contentCls}>
              <SelectItem value="all" className={itemCls}>All Types</SelectItem>
              {tariffTypes.map((t) => (
                <SelectItem key={t} value={t} className={itemCls}>{t}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <div>
          <label className={labelCls}>Vehicle Group</label>
          <Select disabled={!tariffType} onValueChange={handleGroup} value={groupOfVehicle ?? "all"}>
            <SelectTrigger className={triggerCls}>
              {loadingGroups
                ? <Loader2 className="w-3 h-3 animate-spin" />
                : <SelectValue placeholder={tariffType ? "Select group" : "Select type first"} />}
            </SelectTrigger>
            <SelectContent className={contentCls}>
              <SelectItem value="all" className={itemCls}>All Groups</SelectItem>
              {vehicleGroups.map((g) => (
                <SelectItem key={g} value={g} className={itemCls}>{g}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <div>
          <label className={labelCls}>Vehicle Type</label>
          <Select disabled={!groupOfVehicle} onValueChange={handleVehicleType} value={typeOfVehicle ?? "all"}>
            <SelectTrigger className={triggerCls}>
              {loadingVTypes
                ? <Loader2 className="w-3 h-3 animate-spin" />
                : <SelectValue placeholder={groupOfVehicle ? "Select type" : "Select group first"} />}
            </SelectTrigger>
            <SelectContent className={contentCls}>
              <SelectItem value="all" className={itemCls}>All Vehicle Types</SelectItem>
              {vehicleTypes.map((vt) => (
                <SelectItem key={vt} value={vt} className={itemCls}>{vt}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <div>
          <label className={labelCls}>Category / CC</label>
          <Select disabled={!typeOfVehicle} onValueChange={handleCategory} value={category ?? "all"}>
            <SelectTrigger className={triggerCls}>
              {loadingCats
                ? <Loader2 className="w-3 h-3 animate-spin" />
                : <SelectValue placeholder={typeOfVehicle ? "Select category" : "Select type first"} />}
            </SelectTrigger>
            <SelectContent className={contentCls}>
              <SelectItem value="all" className={itemCls}>All Categories</SelectItem>
              {categories.map((c) => (
                <SelectItem key={c} value={c} className={itemCls}>{c}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

      </div>

      {/* Progressive hint */}
      {!isResolved && (
        <p className="font-body text-[10px] text-t4">
          {allSelected && resolving
            ? "Resolving tariff key…"
            : allSelected
            ? "⚠ No matching tariff found for this combination."
            : "Select all 4 levels above to pin the timeline to one tariff's full lifecycle."}
        </p>
      )}
    </div>
  );
}

// ─── Text + Date inputs ───────────────────────────────────────────────────────

interface LocalFilters { changedBy: string; ipAddress: string; from: string; to: string; }
const EMPTY: LocalFilters = { changedBy: "", ipAddress: "", from: "", to: "" };

function TextDateInputs({
  onUpdate,
  onPendingChange,
}: {
  onUpdate:        (patch: Partial<MotorTariffAuditFilterRequest>) => void;
  onPendingChange: (pending: boolean) => void;
}) {
  const [local, setLocal] = useState<LocalFilters>(EMPTY);
  const set = useCallback((key: keyof LocalFilters, value: string) => {
    setLocal((prev) => ({ ...prev, [key]: value }));
  }, []);

  const dChangedBy = useDebounce(local.changedBy, 400);
  const dIpAddress = useDebounce(local.ipAddress, 400);
  const dFrom      = useDebounce(local.from,      600);
  const dTo        = useDebounce(local.to,        600);

  useEffect(() => { onUpdate({ changedBy: dChangedBy || undefined }); }, [dChangedBy]); // eslint-disable-line
  useEffect(() => { onUpdate({ ipAddress: dIpAddress || undefined }); }, [dIpAddress]); // eslint-disable-line
  useEffect(() => { onUpdate({ from: toIso(dFrom) }); },               [dFrom]);        // eslint-disable-line
  useEffect(() => { onUpdate({ to:   toIso(dTo)   }); },               [dTo]);          // eslint-disable-line

  const isPending =
    local.changedBy !== dChangedBy || local.ipAddress !== dIpAddress ||
    local.from !== dFrom           || local.to !== dTo;

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
    "h-7 text-xs font-body bg-surface border-gs-line text-t1 placeholder:text-t4",
    "focus-visible:ring-1 focus-visible:ring-brand focus-visible:border-brand",
  );

  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap gap-2">
        {([
          { key: "changedBy" as const, debounced: dChangedBy, placeholder: "Actor (changedBy)", width: "w-40" },
          { key: "ipAddress" as const, debounced: dIpAddress, placeholder: "IP or prefix",      width: "w-32" },
        ]).map(({ key, debounced, placeholder, width }) => (
          <div key={key} className="relative">
            <Input
              value={local[key]}
              onChange={(e) => set(key, e.target.value)}
              placeholder={placeholder}
              className={cn(inputBase, local[key] !== debounced && "border-brand/40", width)}
            />
            {local[key] !== debounced && (
              <span className="absolute right-1.5 top-1/2 -translate-y-1/2 h-1.5 w-1.5 rounded-full bg-brand animate-pulse" />
            )}
          </div>
        ))}
      </div>

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
            <span className="text-[10px] font-body text-t4">{label}</span>
            <div className="relative">
              <Input
                type="datetime-local"
                value={local[key]}
                onChange={(e) => set(key, e.target.value)}
                className={cn(inputBase, "w-48 pr-2 [color-scheme:light] dark:[color-scheme:dark]", local[key] !== debounced && "border-brand/40")}
              />
              {local[key] !== debounced && (
                <span className="absolute right-1.5 top-1/2 -translate-y-1/2 h-1.5 w-1.5 rounded-full bg-brand animate-pulse" />
              )}
            </div>
          </div>
        ))}

        <div className="flex gap-1">
          {[{ label: "Today", days: 0 }, { label: "7d", days: 7 }, { label: "30d", days: 30 }].map(({ label, days }) => (
            <button key={label} onClick={() => applyPreset(days)}
              className="h-6 px-2 rounded-gs-sm border border-gs-line text-[10px] font-body text-t4 hover:text-t2 hover:border-gs-line-2 transition-colors">
              {label}
            </button>
          ))}
          {(local.from || local.to) && (
            <button onClick={clearDates}
              className="h-6 px-1.5 rounded-gs-sm border border-gs-line text-t4 hover:text-destructive hover:border-destructive/30 transition-colors">
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
  filter:           MotorTariffAuditFilterRequest;
  onUpdate:         (patch: Partial<MotorTariffAuditFilterRequest>) => void;
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
  const [resetKey,      setResetKey]      = useState(0);
  const [isPending,     setIsPending]     = useState(false);
  const [lookupOpen,    setLookupOpen]    = useState(false);
  const [resolvedLabel, setResolvedLabel] = useState<string | undefined>();

  const handleClear = () => {
    setResetKey((k) => k + 1);
    setResolvedLabel(undefined);
    onClear();
  };

  const handleTariffResolved = useCallback((tariffKey: number, label: string) => {
    setResolvedLabel(label);
    onUpdate({ tariffKey });
  }, [onUpdate]);

  const handleTariffCleared = useCallback(() => {
    if (filter.tariffKey != null) {
      setResolvedLabel(undefined);
      onUpdate({ tariffKey: undefined });
    }
  }, [filter.tariffKey, onUpdate]);

  const toggleRevType = (type: string) => {
    const active = filter.revisionTypes?.split(",").filter(Boolean) ?? [];
    const next   = active.includes(type)
      ? active.filter((t) => t !== type)
      : [...active, type];
    onUpdate({ revisionTypes: next.join(",") || undefined });
  };

  const currentPage    = filter.page ?? 0;
  const activeRevTypes = filter.revisionTypes?.split(",").filter(Boolean) ?? [];
  const isLifecycleMode = !!filter.tariffKey;

  return (
    <div className="border-b border-gs-line bg-surface-card shrink-0">

      {/* ── Tariff Lookup collapsible ──────────────────────────────────────── */}
      <div className="px-4 md:px-5 pt-2.5">
        <button
          onClick={() => setLookupOpen((v) => !v)}
          className={cn(
            "w-full flex items-center justify-between px-3 py-2 rounded-gs border transition-colors text-left",
            lookupOpen || isLifecycleMode
              ? "border-brand/40 bg-brand-soft"
              : "border-gs-line bg-surface-2/50 hover:border-gs-line-2",
          )}
        >
          <div className="flex items-center gap-2 min-w-0">
            <Search className={cn("h-3.5 w-3.5 shrink-0", isLifecycleMode || lookupOpen ? "text-brand" : "text-t4")} />
            <span className={cn("font-body text-[11px] font-semibold truncate", isLifecycleMode || lookupOpen ? "text-brand" : "text-t3")}>
              {isLifecycleMode
                ? `Lifecycle view · ${resolvedLabel ?? `Tariff #${filter.tariffKey}`}`
                : "Find a specific tariff — lifecycle view"}
            </span>
            {isLifecycleMode && (
              <span className="inline-flex items-center h-4 px-1.5 rounded-[3px] border bg-brand/10 text-brand border-brand/30 text-[9px] font-bold font-body uppercase shrink-0">
                #{filter.tariffKey}
              </span>
            )}
          </div>
          {lookupOpen
            ? <ChevronUp   className={cn("h-3.5 w-3.5 shrink-0", isLifecycleMode || lookupOpen ? "text-brand" : "text-t4")} />
            : <ChevronDown className={cn("h-3.5 w-3.5 shrink-0", isLifecycleMode || lookupOpen ? "text-brand" : "text-t4")} />}
        </button>

        {lookupOpen && (
          <div className="mt-2 pb-1">
            <TariffLookup
              key={resetKey}
              onTariffResolved={handleTariffResolved}
              onTariffCleared={handleTariffCleared}
              resolvedTariffKey={filter.tariffKey}
            />
          </div>
        )}
      </div>

      {/* ── Standard filters ──────────────────────────────────────────────── */}
      <div className="flex flex-wrap items-start gap-2 px-4 md:px-5 py-2.5">

        <span className="text-[9px] font-bold tracking-widest uppercase text-t4 mt-2 hidden sm:block">
          Filter
        </span>

        <div className="flex-1 min-w-0">
          <TextDateInputs
            key={resetKey}
            onUpdate={onUpdate}
            onPendingChange={setIsPending}
          />
        </div>

        {/* Rev-type toggles */}
        <div className="flex flex-wrap gap-1.5 mt-0.5">
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

        {(hasActiveFilters || isPending) && (
          <Button variant="ghost" size="sm" onClick={handleClear}
            className="h-7 px-2 text-xs font-body text-t3 hover:text-t1 hover:bg-surface-2 mt-0.5">
            <X className="h-3 w-3 mr-1" /> Clear all
          </Button>
        )}

        <div className="flex items-center gap-3 ml-auto">
          <span className="hidden sm:inline-flex items-center h-5 px-2 rounded-full bg-surface-3 border border-gs-line text-[10px] font-body text-t3">
            {totalElements.toLocaleString()} events
          </span>

          {totalPages > 1 && (
            <div className="flex items-center gap-1">
              <Button variant="outline" size="icon"
                className="h-6 w-6 border-gs-line text-t3 hover:text-t1 hover:bg-surface-2"
                onClick={() => onPageChange(currentPage - 1)} disabled={currentPage === 0}>
                <ChevronLeft className="h-3 w-3" />
              </Button>
              <span className="text-[10px] font-body text-t3 min-w-[48px] text-center">
                {currentPage + 1} / {totalPages}
              </span>
              <Button variant="outline" size="icon"
                className="h-6 w-6 border-gs-line text-t3 hover:text-t1 hover:bg-surface-2"
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