"use client";

import { useState, useEffect, useCallback } from "react";
import {
  SlidersHorizontal, ChevronDown, ChevronUp,
  ChevronLeft, ChevronRight, X,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useDebounce } from "@/lib/hooks/useDebounce";
import type { AuthAuditFilterRequest } from "../auth_audit.types";

// ─── Event-type quick-toggle config ──────────────────────────────────────────

const EVENT_TYPE_TOGGLES = [
  { name: "LOGIN_FAILED",          label: "Login Fail",    cls: "border-rose-500/30   bg-rose-500/10   text-rose-600"   },
  { name: "BRUTE_FORCE_DETECTED",  label: "Brute Force",   cls: "border-red-500/30    bg-red-500/10    text-red-700"    },
  { name: "UNAUTHORIZED_ACCESS",   label: "Unauth Access", cls: "border-red-500/30    bg-red-500/10    text-red-700"    },
  { name: "PASSWORD_RESET_FAILED", label: "PW Reset Fail", cls: "border-amber-500/30  bg-amber-500/10  text-amber-600"  },
  { name: "RATE_LIMIT_EXCEEDED",   label: "Rate Limit",    cls: "border-amber-500/30  bg-amber-500/10  text-amber-600"  },
  { name: "SIGNUP_FAILED",         label: "Signup Fail",   cls: "border-rose-500/30   bg-rose-500/10   text-rose-600"   },
] as const;

// ─── Helpers ─────────────────────────────────────────────────────────────────

function toIso(v: string): string | undefined {
  if (!v) return undefined;
  return v.length === 16 ? `${v}:00` : v;
}

// ─── Local state shape for debounced text inputs ──────────────────────────────

interface LocalFilters {
  userEmail:  string;
  ipAddress:  string;
  requestId:  string;
  from:       string;
  to:         string;
}
const EMPTY_LOCAL: LocalFilters = {
  userEmail: "", ipAddress: "", requestId: "", from: "", to: "",
};

// ─── FilterInputs — uncontrolled, remounted on clear via resetKey ─────────────

function FilterInputs({
  onUpdate,
  onPendingChange,
}: {
  onUpdate:        (patch: Partial<AuthAuditFilterRequest>) => void;
  onPendingChange: (pending: boolean) => void;
}) {
  const [local, setLocal] = useState<LocalFilters>(EMPTY_LOCAL);

  const set = useCallback((key: keyof LocalFilters, value: string) => {
    setLocal((prev) => ({ ...prev, [key]: value }));
  }, []);

  const dUserEmail = useDebounce(local.userEmail, 400);
  const dIpAddress = useDebounce(local.ipAddress, 400);
  const dRequestId = useDebounce(local.requestId, 600); // longer — UUID paste, not keystroke
  const dFrom      = useDebounce(local.from,      600);
  const dTo        = useDebounce(local.to,        600);

  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { onUpdate({ userEmail:  dUserEmail  || undefined }); }, [dUserEmail]);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { onUpdate({ ipAddress:  dIpAddress  || undefined }); }, [dIpAddress]);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { onUpdate({ requestId:  dRequestId  || undefined }); }, [dRequestId]);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { onUpdate({ from:       toIso(dFrom) });             }, [dFrom]);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { onUpdate({ to:         toIso(dTo) });               }, [dTo]);

  const isPending =
    local.userEmail !== dUserEmail ||
    local.ipAddress !== dIpAddress ||
    local.requestId !== dRequestId ||
    local.from      !== dFrom      ||
    local.to        !== dTo;

  useEffect(() => { onPendingChange(isPending); }, [isPending, onPendingChange]);

  const inputCls =
    "h-7 w-full rounded-gs-sm border border-gs-line bg-surface px-2.5 " +
    "font-body text-[11px] text-t1 placeholder:text-t4 " +
    "focus:outline-none focus:border-brand/50 transition-colors";

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">

      <div className="flex flex-col gap-1">
        <label className="font-body text-[9px] text-t4 uppercase tracking-widest">User Email</label>
        <input
          className={inputCls}
          placeholder="alice@example.com"
          value={local.userEmail}
          onChange={(e) => set("userEmail", e.target.value)}
        />
      </div>

      <div className="flex flex-col gap-1">
        <label className="font-body text-[9px] text-t4 uppercase tracking-widest">IP Address</label>
        <input
          className={inputCls}
          placeholder="192.168.1.1"
          value={local.ipAddress}
          onChange={(e) => set("ipAddress", e.target.value)}
        />
      </div>

      <div className="flex flex-col gap-1 sm:col-span-2 lg:col-span-1">
        <label className="font-body text-[9px] text-t4 uppercase tracking-widest">
          Trace ID (X-Request-ID)
        </label>
        <input
          className={cn(inputCls, "font-mono text-[10px]")}
          placeholder="550e8400-e29b-41d4-a716-…"
          value={local.requestId}
          onChange={(e) => set("requestId", e.target.value)}
        />
      </div>

      <div className="flex flex-col gap-1">
        <label className="font-body text-[9px] text-t4 uppercase tracking-widest">From</label>
        <input
          type="datetime-local"
          className={inputCls}
          value={local.from}
          onChange={(e) => set("from", e.target.value)}
        />
      </div>

      <div className="flex flex-col gap-1">
        <label className="font-body text-[9px] text-t4 uppercase tracking-widest">To</label>
        <input
          type="datetime-local"
          className={inputCls}
          value={local.to}
          onChange={(e) => set("to", e.target.value)}
        />
      </div>

    </div>
  );
}

// ─── ActivePills ──────────────────────────────────────────────────────────────

function ActivePills({ filter }: { filter: AuthAuditFilterRequest }) {
  const pills: string[] = [];
  if (filter.eventType)       pills.push(`type: ${filter.eventType}`);
  if (filter.userEmail)       pills.push(`email: ${filter.userEmail}`);
  if (filter.ipAddress)       pills.push(`ip: ${filter.ipAddress}`);
  if (filter.requestId)       pills.push(`trace: ${filter.requestId.slice(0, 8)}…`);
  if (filter.success != null) pills.push(`success: ${filter.success}`);
  if (filter.from || filter.to) pills.push("date range");

  if (pills.length === 0) return null;

  return (
    <div className="flex flex-wrap gap-1.5 px-4 pb-2">
      {pills.map((label, i) => (
        <span
          key={i}
          className="inline-flex items-center h-5 px-2 rounded-full border border-brand/30 bg-brand-soft text-[10px] font-body text-brand font-medium"
        >
          {label}
        </span>
      ))}
    </div>
  );
}

// ─── FilterBar ────────────────────────────────────────────────────────────────

interface FilterBarProps {
  filter:           AuthAuditFilterRequest;
  onUpdate:         (patch: Partial<AuthAuditFilterRequest>) => void;
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
  const [resetKey,    setResetKey]    = useState(0);
  const [isPending,   setIsPending]   = useState(false);
  const [filtersOpen, setFiltersOpen] = useState(false);

  const handleClear = () => {
    setResetKey((k) => k + 1);
    onClear();
  };

  const toggleEventType = (name: string) => {
    onUpdate({ eventType: filter.eventType === name ? undefined : name });
  };

  const toggleSuccess = (val: boolean) => {
    onUpdate({ success: filter.success === val ? undefined : val });
  };

  const currentPage = filter.page ?? 0;

  const activeCount = [
    filter.eventType,
    filter.userEmail,
    filter.ipAddress,
    filter.requestId,
    filter.success != null ? true : undefined,
    filter.from || filter.to,
  ].filter(Boolean).length;

  return (
    <div className="border-b border-gs-line bg-surface-card shrink-0">

      {/* ── Always-visible toolbar row ──────────────────────────────────── */}
      <div className="flex items-center gap-2 px-4 md:px-5 py-2 flex-wrap">

        {/* Filters toggle */}
        <button
          onClick={() => setFiltersOpen((v) => !v)}
          className={cn(
            "flex items-center gap-1.5 h-7 px-2.5 rounded-gs-sm border text-[11px] font-body font-semibold transition-colors shrink-0",
            filtersOpen || hasActiveFilters
              ? "border-brand/40 bg-brand-soft text-brand"
              : "border-gs-line text-t3 hover:border-gs-line-2 hover:text-t2",
          )}
        >
          <SlidersHorizontal className="h-3.5 w-3.5 shrink-0" />
          Filters
          {activeCount > 0 && (
            <span className="inline-flex items-center justify-center h-4 w-4 rounded-full bg-brand text-white text-[9px] font-bold">
              {activeCount}
            </span>
          )}
          {isPending && (
            <span className="h-1.5 w-1.5 rounded-full bg-brand animate-pulse" />
          )}
          {filtersOpen
            ? <ChevronUp   className="h-3 w-3 shrink-0" />
            : <ChevronDown className="h-3 w-3 shrink-0" />}
        </button>

        {/* Event-type quick-toggles */}
        <div className="flex flex-wrap gap-1">
          {EVENT_TYPE_TOGGLES.map(({ name, label, cls }) => {
            const active = filter.eventType === name;
            return (
              <button
                key={name}
                onClick={() => toggleEventType(name)}
                className={cn(
                  "h-7 px-2 rounded-gs-sm border text-[10px] font-bold font-body tracking-wide transition-colors",
                  active
                    ? cls
                    : "border-gs-line text-t4 bg-surface hover:border-gs-line-2 hover:text-t3",
                )}
              >
                {label}
              </button>
            );
          })}
        </div>

        {/* Success / Failed toggles — right-aligned */}
        <div className="flex gap-1 ml-auto">
          <button
            onClick={() => toggleSuccess(true)}
            className={cn(
              "h-7 px-2.5 rounded-gs-sm border text-[10px] font-bold font-body tracking-wide transition-colors",
              filter.success === true
                ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-600"
                : "border-gs-line text-t4 hover:border-gs-line-2 hover:text-t3",
            )}
          >
            ✓ Success
          </button>
          <button
            onClick={() => toggleSuccess(false)}
            className={cn(
              "h-7 px-2.5 rounded-gs-sm border text-[10px] font-bold font-body tracking-wide transition-colors",
              filter.success === false
                ? "bg-rose-500/10 border-rose-500/30 text-rose-600"
                : "border-gs-line text-t4 hover:border-gs-line-2 hover:text-t3",
            )}
          >
            ✗ Failed
          </button>
        </div>
      </div>

      {/* ── Collapsible advanced filter inputs ──────────────────────────── */}
      {filtersOpen && (
        <div className="px-4 pb-3 pt-1 border-t border-gs-line">
          <FilterInputs
            key={resetKey}
            onUpdate={onUpdate}
            onPendingChange={setIsPending}
          />
        </div>
      )}

      {/* ── Active filter pills ─────────────────────────────────────────── */}
      <ActivePills filter={filter} />

      {/* ── Pagination + summary row ────────────────────────────────────── */}
      <div className="flex items-center justify-between px-4 md:px-5 py-1.5 border-t border-gs-line">
        <span className="font-body text-[11px] text-t4">
          {totalElements.toLocaleString()} event{totalElements !== 1 ? "s" : ""}
          {hasActiveFilters && " (filtered)"}
        </span>
        <div className="flex items-center gap-1">
          <button
            disabled={currentPage === 0}
            onClick={() => onPageChange(currentPage - 1)}
            className="flex h-6 w-6 items-center justify-center rounded border border-gs-line text-t3 hover:text-t1 disabled:opacity-30 transition-colors"
          >
            <ChevronLeft className="h-3.5 w-3.5" />
          </button>
          <span className="font-body text-[11px] text-t3 tabular-nums px-1">
            {currentPage + 1} / {Math.max(totalPages, 1)}
          </span>
          <button
            disabled={currentPage >= totalPages - 1}
            onClick={() => onPageChange(currentPage + 1)}
            className="flex h-6 w-6 items-center justify-center rounded border border-gs-line text-t3 hover:text-t1 disabled:opacity-30 transition-colors"
          >
            <ChevronRight className="h-3.5 w-3.5" />
          </button>
          {hasActiveFilters && (
            <button
              onClick={handleClear}
              className="ml-2 h-6 px-2 rounded border border-gs-line text-[10px] font-body text-t3 hover:text-destructive hover:border-destructive/30 transition-colors"
            >
              Clear all
            </button>
          )}
        </div>
      </div>

    </div>
  );
}