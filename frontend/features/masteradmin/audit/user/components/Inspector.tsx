"use client";

import { useRevisionDetail } from "@/features/masteradmin/audit/user/user.react.query";
import type { AuditTimelineItemDTO } from "@/features/masteradmin/audit/user/user.types";
import { cn } from "@/lib/utils";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { RevBadge, IPLabel, RolePill, formatTs } from "./UiPrimitives";
import { DiffTable } from "./DiffTable";

// ─── Empty ────────────────────────────────────────────────────────────────────

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

// ─── Loading ──────────────────────────────────────────────────────────────────

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

// ─── Error ────────────────────────────────────────────────────────────────────

function InspectorError() {
  return (
    <div className="flex h-full items-center justify-center p-8">
      <p className="font-body text-sm text-destructive">Failed to load revision details.</p>
    </div>
  );
}

// ─── Section ──────────────────────────────────────────────────────────────────

function Section({
  label,
  children,
  className,
}: {
  label:     string;
  children:  React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("rounded-gs border border-gs-line bg-surface-card overflow-hidden", className)}>
      <div className="px-4 py-2 border-b border-gs-line bg-surface-2/50">
        <span className="font-body text-[10px] font-bold tracking-widest uppercase text-t4">
          {label}
        </span>
      </div>
      {children}
    </div>
  );
}

// ─── Identity row ─────────────────────────────────────────────────────────────

function IdentityRow({ label, value }: { label: string; value: string | number | null }) {
  return (
    <div className="flex items-baseline gap-2 mb-2 last:mb-0">
      <span className="font-body text-[11px] text-t4 min-w-[72px] shrink-0">{label}</span>
      <span className="font-body text-xs text-t2 break-all">{value ?? "—"}</span>
    </div>
  );
}

// ─── Inspector ────────────────────────────────────────────────────────────────

interface InspectorProps {
  selectedItem: AuditTimelineItemDTO | null;
}

export function Inspector({ selectedItem }: InspectorProps) {
  const { data: detail, isLoading, isError } = useRevisionDetail(
    selectedItem?.userId,
    selectedItem?.revisionNumber,
  );

  if (!selectedItem)            return <InspectorEmpty />;
  if (isLoading)                return <InspectorLoading revNum={selectedItem.revisionNumber} />;
  if (isError || !detail?.data) return <InspectorError />;

  const data          = detail.data;
  const { date, time } = formatTs(data.timestamp);

  return (
    <div className="p-4 md:p-5 space-y-3 overflow-y-auto">

      {/* Header */}
      <div className="mb-1">
        <div className="flex items-center gap-2 mb-0.5 flex-wrap">
          <span className="font-body text-[10px] font-medium tracking-widest uppercase text-t4">
            Revision
          </span>
          <span className="font-head text-xl font-bold text-brand">
            #{data.revisionNumber}
          </span>
          <RevBadge type={data.revisionType} />
        </div>
        <p className="font-body text-[11px] text-t4">
          {date} · {time}
        </p>
      </div>

      {/* Alert: critical change */}
      {data.diff?.criticalChange && (
        <Alert className="border-destructive/30 bg-destructive/5 rounded-gs">
          <span className="mr-2">🚩</span>
          <AlertTitle className="font-head text-xs font-bold text-destructive">
            Critical State Change
          </AlertTitle>
          <AlertDescription className="font-body text-[11px] text-destructive/60 mt-1">
            {data.accountLocked && "Account is locked. "}
            {!data.enabled      && "Account is disabled."}
          </AlertDescription>
        </Alert>
      )}

      {/* Alert: admin escalation */}
      {data.diff?.adminEscalation && (
        <Alert className="border-brand-border bg-brand-soft rounded-gs">
          <span className="mr-2">👑</span>
          <AlertTitle className="font-head text-xs font-bold text-brand">
            Admin Role Escalation
          </AlertTitle>
          <AlertDescription className="font-body text-[11px] text-brand/60 mt-1">
            ROLE_ADMIN was granted in this revision.
          </AlertDescription>
        </Alert>
      )}

      {/* Identity */}
      <Section label="Identity">
        <div className="px-4 py-3">
          <IdentityRow label="User ID"  value={data.userId}       />
          <IdentityRow label="Username" value={data.username}     />
          <IdentityRow label="Email"    value={data.email}        />
          <IdentityRow label="Sign-up"  value={data.signUpMethod} />
          <div className="flex items-center gap-2 mb-2">
            <span className="font-body text-[11px] text-t4 min-w-[72px]">IP</span>
            <IPLabel ip={data.ipAddress} />
          </div>
          <div className="flex items-center gap-2">
            <span className="font-body text-[11px] text-t4 min-w-[72px]">Actor</span>
            <span className="font-body text-xs font-semibold text-t1">{data.changedBy}</span>
            {data.diff?.previousChangedBy && (
              <span className="font-body text-[10px] text-t4">
                (prev by {data.diff.previousChangedBy})
              </span>
            )}
          </div>
        </div>
      </Section>

      {/* Delta */}
      <Section label={`Δ Delta · ${data.diff?.changedFields.length ?? 0} field${(data.diff?.changedFields.length ?? 0) !== 1 ? "s" : ""} changed`}>
        {data.diff ? (
          <DiffTable diff={data.diff} currentRevision={data.revisionNumber} />
        ) : (
          <div className="px-4 py-5 font-body text-xs text-t4 text-center">
            First revision — no previous state to compare.
          </div>
        )}
      </Section>

      {/* Current Roles */}
      <Section label="Current Roles">
        <div className="px-4 py-3 flex flex-wrap">
          {data.roles.length > 0
            ? data.roles.map((r: string) => <RolePill key={r} role={r} />)
            : <span className="font-body text-xs text-t4">No roles assigned</span>
          }
        </div>
      </Section>

    </div>
  );
}