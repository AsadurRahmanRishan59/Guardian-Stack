"use client";

import { useMotorTariffRevisionDetail } from "@/features/masteradmin/audit/motortariff/motortariff_audit_react_query";
import type { MotorTariffAuditTimelineItemDTO } from "@/features/masteradmin/audit/motortariff/motortariff_audit_types";
import { cn } from "@/lib/utils";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { DiffTable } from "./DiffTable";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function formatTs(iso: string): string {
  return new Date(iso).toLocaleString("en-GB", {
    year: "numeric", month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}

function RevBadge({ type }: { type: string }) {
  const cls =
    type === "CREATED"  ? "bg-gs-green-bg    text-gs-green   border-gs-green/30" :
    type === "MODIFIED" ? "bg-brand-soft     text-brand      border-brand/30"    :
                          "bg-destructive/10 text-destructive border-destructive/30";
  return (
    <span className={cn("inline-flex items-center h-5 px-2 rounded-[3px] border text-[10px] font-bold font-body tracking-widest uppercase", cls)}>
      {type}
    </span>
  );
}

// ─── States ───────────────────────────────────────────────────────────────────

function InspectorEmpty() {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-3 p-8">
      <span className="text-4xl">🔍</span>
      <p className="font-body text-sm text-t3 text-center max-w-[180px] leading-relaxed">
        Select a revision from the timeline to inspect
      </p>
    </div>
  );
}

function InspectorLoading({ revNum }: { revNum: number }) {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-4 p-8">
      <span className="font-body text-[11px] text-t4 tracking-widest uppercase">
        Loading Revision #{revNum}…
      </span>
      <div className="w-48 h-0.5 bg-surface-3 overflow-hidden rounded-full">
        <div className="h-full w-2/5 bg-brand rounded-full animate-[slide_1.2s_ease-in-out_infinite]" />
      </div>
    </div>
  );
}

function InspectorError() {
  return (
    <div className="flex h-full items-center justify-center p-8">
      <p className="font-body text-sm text-destructive">Failed to load revision details.</p>
    </div>
  );
}

function Section({ label, children, className }: { label: string; children: React.ReactNode; className?: string }) {
  return (
    <div className={cn("rounded-gs border border-gs-line bg-surface-card overflow-hidden", className)}>
      <div className="px-4 py-2 border-b border-gs-line bg-surface-2/50">
        <span className="font-body text-[10px] font-bold tracking-widest uppercase text-t4">{label}</span>
      </div>
      {children}
    </div>
  );
}

function IdentityRow({ label, value }: { label: string; value: string | number | null | undefined }) {
  return (
    <div className="flex items-baseline gap-2 mb-2 last:mb-0">
      <span className="font-body text-[11px] text-t4 min-w-[80px] shrink-0">{label}</span>
      <span className="font-body text-xs text-t2 break-all">{value ?? "—"}</span>
    </div>
  );
}

function MoneyRow({ label, value }: { label: string; value: string | null | undefined }) {
  const num = value ? parseFloat(value) : null;
  return (
    <div className="flex items-center justify-between py-1.5 border-b border-gs-line last:border-0 px-3">
      <span className="font-body text-[11px] text-t3">{label}</span>
      <span className="font-body text-xs tabular-nums text-t1 font-medium">
        {num != null ? `৳ ${num.toLocaleString("en-BD", { minimumFractionDigits: 2 })}` : "—"}
      </span>
    </div>
  );
}

function RateRow({ label, value }: { label: string; value: string | null | undefined }) {
  return (
    <div className="flex items-center justify-between py-1.5 border-b border-gs-line last:border-0 px-3">
      <span className="font-body text-[11px] text-t3">{label}</span>
      <span className="font-body text-xs tabular-nums text-t1">{value ?? "—"}%</span>
    </div>
  );
}

// ─── Inspector ────────────────────────────────────────────────────────────────

interface InspectorProps {
  selectedItem: MotorTariffAuditTimelineItemDTO | null;
}

export function Inspector({ selectedItem }: InspectorProps) {
  const { data: response, isLoading, isError } = useMotorTariffRevisionDetail(
    selectedItem?.tariffKey,
    selectedItem?.revisionNumber,
  );

  if (!selectedItem) return <InspectorEmpty />;
  if (isLoading)     return <InspectorLoading revNum={selectedItem.revisionNumber} />;
  if (isError || !response?.data) return <InspectorError />;

  const dto = response.data;

  return (
    <div className="flex flex-col gap-4 p-4 min-h-full">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <RevBadge type={dto.revisionType} />
          <span className="font-body text-xs text-t3 tabular-nums">#{dto.revisionNumber}</span>
        </div>
        <span className="font-body text-[11px] text-t4">{formatTs(dto.timestamp)}</span>
      </div>

      {/* Critical / status alert */}
      {dto.diff?.criticalChange && (
        <Alert className="border-amber-500/30 bg-amber-500/5">
          <AlertTitle className="font-body text-xs font-bold text-amber-600">Status Changed</AlertTitle>
          <AlertDescription className="font-body text-xs text-t3">
            Active status was toggled in this revision.
          </AlertDescription>
        </Alert>
      )}

      {/* Revision metadata */}
      <Section label="Revision Metadata">
        <div className="p-3">
          <IdentityRow label="Changed by" value={dto.changedBy} />
          <IdentityRow label="IP Address" value={dto.ipAddress} />
          <IdentityRow label="Tariff Key" value={dto.tariffKey} />
          <IdentityRow label="Active"     value={dto.isActive ? "Yes" : "No"} />
        </div>
      </Section>

      {/* Tariff identity */}
      <Section label="Tariff Identity">
        <div className="p-3">
          <IdentityRow label="Type"      value={dto.tariffType} />
          <IdentityRow label="Group"     value={dto.groupOfVehicle} />
          <IdentityRow label="Vehicle"   value={dto.typeOfVehicle} />
          <IdentityRow label="Category"  value={dto.category} />
        </div>
      </Section>

      {/* Financial snapshot */}
      <Section label="Premium Rates (Snapshot)">
        <MoneyRow label="Own DP Basic"     value={dto.ownDpBasic} />
        <MoneyRow label="Act Liability"    value={dto.actLiability} />
        <RateRow  label="Full Ins Value %" value={dto.fullInsValue} />
        <RateRow  label="Fire %"           value={dto.fire} />
        <RateRow  label="Theft %"          value={dto.theft} />
        <RateRow  label="Cyclone %"        value={dto.cyclone} />
        <RateRow  label="Earthquake %"     value={dto.earthquake} />
      </Section>

      {/* Diff */}
      {dto.diff ? (
        <Section label="Field Diff">
          <DiffTable diff={dto.diff} currentRevision={dto.revisionNumber} />
        </Section>
      ) : (
        <Section label="Field Diff">
          <div className="px-4 py-3">
            <span className="font-body text-xs text-t4">First revision — no predecessor to diff against.</span>
          </div>
        </Section>
      )}

    </div>
  );
}