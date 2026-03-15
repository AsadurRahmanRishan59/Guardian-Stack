"use client";

import { cn } from "@/lib/utils";
import type { AuditLevel, AuthAuditTimelineItemDTO } from "../auth_audit.types";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function formatTs(iso: string): string {
  return new Date(iso).toLocaleString("en-GB", {
    year: "numeric", month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}

/** Attempt to pretty-print a string as JSON; return original string on failure. */
function tryPrettyJson(raw: string | null | undefined): string | null {
  if (!raw) return null;
  try {
    return JSON.stringify(JSON.parse(raw), null, 2);
  } catch {
    return raw;
  }
}

// ─── Outcome badge ────────────────────────────────────────────────────────────

function OutcomeBadge({ success }: { success: boolean }) {
  return (
    <span
      className={cn(
        "inline-flex items-center h-5 px-2 rounded-[3px] border text-[10px] font-bold font-body tracking-widest uppercase",
        success
          ? "bg-emerald-500/10 text-emerald-600 border-emerald-500/30"
          : "bg-rose-500/10    text-rose-600    border-rose-500/30",
      )}
    >
      {success ? "SUCCESS" : "FAILED"}
    </span>
  );
}

// ─── Level badge ─────────────────────────────────────────────────────────────

const LEVEL_BORDER: Record<AuditLevel, string> = {
  DEBUG:    "border-gs-line       text-t4",
  INFO:     "border-gs-line       text-t3",
  WARN:     "border-amber-500/40  text-amber-600",
  CRITICAL: "border-red-500/40    text-red-600",
};

function LevelBadge({ level }: { level: AuditLevel }) {
  return (
    <span
      className={cn(
        "inline-flex items-center h-5 px-2 rounded-[3px] border text-[10px] font-bold font-body tracking-widest uppercase",
        "bg-surface-3",
        LEVEL_BORDER[level],
      )}
    >
      {level}
    </span>
  );
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function Section({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="rounded-gs border border-gs-line overflow-hidden">
      <div className="px-3 py-1.5 bg-surface-2/60 border-b border-gs-line">
        <span className="font-body text-[10px] font-semibold text-t4 tracking-widest uppercase">
          {label}
        </span>
      </div>
      {children}
    </div>
  );
}

function DataRow({
  label,
  value,
  mono = false,
  valueClass,
  copyable = false,
}: {
  label:       string;
  value:       string | null | undefined;
  mono?:       boolean;
  valueClass?: string;
  copyable?:   boolean;
}) {
  const handleCopy = () => {
    if (value) navigator.clipboard.writeText(value);
  };

  return (
    <div className="flex items-start justify-between gap-3 py-1.5 border-b border-gs-line last:border-0 px-3 group">
      <span className="font-body text-[11px] text-t3 shrink-0">{label}</span>
      <div className="flex items-center gap-1.5 min-w-0">
        <span
          className={cn(
            "font-body text-xs text-right break-all",
            mono ? "font-mono text-[10px]" : "",
            valueClass ?? "text-t1",
            !value && "text-t4 italic",
          )}
        >
          {value ?? "—"}
        </span>
        {copyable && value && (
          <button
            onClick={handleCopy}
            title="Copy to clipboard"
            className="shrink-0 opacity-0 group-hover:opacity-100 transition-opacity text-t4 hover:text-t2"
          >
            {/* Simple copy icon using SVG to avoid an extra import */}
            <svg
              xmlns="http://www.w3.org/2000/svg"
              viewBox="0 0 16 16"
              fill="currentColor"
              className="h-3 w-3"
            >
              <path d="M4 2a2 2 0 0 1 2-2h6a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V2zm2-1a1 1 0 0 0-1 1v10a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1V2a1 1 0 0 0-1-1H6z" />
              <path d="M2 5a1 1 0 0 0-1 1v8a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1v-1H2V6a1 1 0 0 0-1-1z" />
            </svg>
          </button>
        )}
      </div>
    </div>
  );
}

// ─── JSON viewer ─────────────────────────────────────────────────────────────

function JsonBlock({ raw }: { raw: string | null | undefined }) {
  const formatted = tryPrettyJson(raw);
  if (!formatted) {
    return (
      <p className="px-3 py-2 font-body text-[11px] text-t4 italic">No data</p>
    );
  }
  return (
    <pre className="px-3 py-2 font-mono text-[10px] text-t2 whitespace-pre-wrap break-all overflow-x-auto leading-relaxed">
      {formatted}
    </pre>
  );
}

// ─── Empty / null state ───────────────────────────────────────────────────────

function InspectorEmpty() {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-3 p-8">
      <span className="text-4xl">🔍</span>
      <p className="font-body text-sm text-t3 text-center max-w-[180px] leading-relaxed">
        Select a security event from the timeline to inspect
      </p>
    </div>
  );
}

// ─── Inspector ────────────────────────────────────────────────────────────────

interface InspectorProps {
  selectedItem: AuthAuditTimelineItemDTO | null;
}

export function Inspector({ selectedItem }: InspectorProps) {
  if (!selectedItem) return <InspectorEmpty />;

  const item = selectedItem;

  return (
    <div className="flex flex-col gap-4 p-4 min-h-full">

      {/* ── Header ─────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div className="flex items-center gap-2 flex-wrap">
          <OutcomeBadge success={item.success} />
          <LevelBadge level={item.level} />
          <span
            className={cn(
              "font-body text-xs font-semibold",
              item.success ? "text-emerald-600" : "text-rose-600",
            )}
          >
            {item.eventType}
          </span>
        </div>
        <span className="font-body text-[11px] text-t4 tabular-nums">
          {formatTs(item.timestamp)}
        </span>
      </div>

      {/* Description */}
      <p className="font-body text-[11px] text-t3 -mt-2">
        {item.eventDescription}
      </p>

      {/* ── Failure alert ──────────────────────────────────────────────── */}
      {!item.success && item.failureReason && (
        <div className="rounded-gs border border-rose-500/30 bg-rose-500/5 px-3 py-2">
          <p className="font-body text-[10px] font-bold text-rose-600 uppercase tracking-widest mb-0.5">
            Failure Reason
          </p>
          <p className="font-body text-xs text-t2">{item.failureReason}</p>
        </div>
      )}

      {/* ── User Info ──────────────────────────────────────────────────── */}
      <Section label="User Info">
        <DataRow label="Email"   value={item.userEmail} />
        <DataRow label="User ID" value={item.userId != null ? String(item.userId) : null} mono />
      </Section>

      {/* ── Technical Details ─────────────────────────────────────────── */}
      <Section label="Technical Details">
        <DataRow
          label="IP Address"
          value={item.ipAddress}
          mono
          copyable
        />
        <DataRow
          label="User Agent"
          value={item.userAgent}
          valueClass="text-t2 text-[10px]"
        />
        {/*
          requestId / Trace ID
          ─────────────────────
          This UUID ties three observability layers together:
            1. This DB row   — stored in gs_auth_audit_logs.request_id
            2. ELK document  — indexed as trace.id by Logstash
            3. HTTP client   — returned as X-Request-ID response header

          For pre-migration rows the value is null; we show a subtle note
          rather than a blank dash so the analyst understands why it's absent.
        */}
        <DataRow
          label="Trace ID (requestId)"
          value={item.requestId}
          mono
          copyable
          valueClass={item.requestId ? "text-t1" : "text-t4 italic text-[10px]"}
        />
        {!item.requestId && (
          <p className="px-3 pb-1.5 font-body text-[9px] text-t4 italic -mt-1">
            Not available — row predates the request_id migration
          </p>
        )}
        <DataRow
          label="Log Row ID"
          value={String(item.id)}
          mono
        />
      </Section>

      {/* ── Metadata — JSON viewer ────────────────────────────────────── */}
      <Section label="Additional Info">
        <JsonBlock raw={item.additionalInfo} />
      </Section>

    </div>
  );
}