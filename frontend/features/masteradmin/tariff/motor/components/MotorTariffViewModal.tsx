// features/masteradmin/tariff/motor/MotorTariffViewModal.tsx
"use client";

import React from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import {
  Car,
  CheckCircle,
  XCircle,
  Loader2,
  Calendar,
  Percent,
  DollarSign,
  ShieldCheck,
  FlameKindling,
  Wind,
  Mountain,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useMotorTariffById } from "../motor.tariff.react-query";

interface MotorTariffViewModalProps {
  tariffKey: number;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

function formatDate(d?: string | null): string {
  if (!d) return "—";
  return new Date(d).toLocaleString("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function formatMoney(v: number): string {
  return new Intl.NumberFormat("en-BD", { minimumFractionDigits: 2 }).format(v);
}

function formatRate(v: number): string {
  return `${v.toFixed(2)}%`;
}

// ── Small card components ──────────────────────────────────────────────────────
function InfoCard({
  title,
  icon,
  children,
}: {
  title: string;
  icon?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-gs border border-gs-line overflow-hidden">
      <div className="flex items-center gap-1.5 px-3 py-2 bg-surface-2 border-b border-gs-line">
        {icon && <span className="text-t3">{icon}</span>}
        <h3 className="text-[10px] font-bold uppercase tracking-widest text-t3">
          {title}
        </h3>
      </div>
      <div className="p-3">{children}</div>
    </div>
  );
}

function InfoRow({
  icon,
  label,
  value,
}: {
  icon?: React.ReactNode;
  label: string;
  value: React.ReactNode;
}) {
  return (
    <div className="flex items-start gap-2.5">
      {icon && <div className="mt-0.5 shrink-0 text-t3">{icon}</div>}
      <div className="flex-1 min-w-0">
        <p className="text-[10px] text-t4 uppercase tracking-wide mb-0.5">{label}</p>
        <div className="text-sm text-t1">{value}</div>
      </div>
    </div>
  );
}

function RateMetric({
  label,
  value,
  icon,
}: {
  label: string;
  value: number;
  icon: React.ReactNode;
}) {
  return (
    <div className="p-2.5 rounded-gs border border-gs-line bg-surface-2/40 flex flex-col gap-1">
      <div className="flex items-center gap-1.5 text-t3">
        {icon}
        <span className="text-[10px] font-semibold uppercase tracking-wide">{label}</span>
      </div>
      <p className="text-base font-bold text-t1">{formatRate(value)}</p>
    </div>
  );
}

export function MotorTariffViewModal({
  tariffKey,
  open,
  onOpenChange,
}: MotorTariffViewModalProps) {
  const [queryEnabled, setQueryEnabled] = React.useState(false);

  React.useEffect(() => {
    if (open && tariffKey) setQueryEnabled(true);
  }, [open, tariffKey]);

  const { data, isLoading, error } = useMotorTariffById(
    queryEnabled ? tariffKey : undefined
  );

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-3xl max-h-[95vh] p-0 gap-0 overflow-hidden border-gs-line bg-surface-card">

        {/* ── Fixed header ── */}
        <DialogHeader className="px-4 pt-4 pb-3 border-b border-gs-line bg-surface-2/60">
          <div className="flex items-start gap-3">
            <div className="shrink-0 w-11 h-11 rounded-gs bg-brand flex items-center justify-center shadow-sm">
              <Car className="h-5 w-5 text-white" />
            </div>

            <div className="flex-1 min-w-0">
              <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-2">
                <div className="min-w-0">
                  <DialogTitle className="text-base font-bold font-head text-t1 leading-tight">
                    {isLoading ? (
                      <span className="text-t4">Loading…</span>
                    ) : data ? (
                      data.typeOfVehicle
                    ) : (
                      "Tariff Details"
                    )}
                  </DialogTitle>
                  {data && (
                    <div className="mt-0.5 space-y-0.5">
                      <p className="text-xs text-t3">{data.groupOfVehicle}</p>
                      <p className="text-[10px] text-t4 font-mono">
                        Tariff #{data.tariffKey}
                      </p>
                    </div>
                  )}
                </div>

                {data && (
                  <div className="flex flex-wrap gap-1.5 shrink-0">
                    <Badge className="text-[10px] bg-surface-3 text-t2 border-gs-line">
                      {data.tariffType}
                    </Badge>
                    <Badge
                      className={cn(
                        "text-[10px] gap-1",
                        data.isActive
                          ? "bg-gs-green-bg text-gs-green border-transparent"
                          : "bg-destructive/10 text-destructive border-destructive/20"
                      )}
                    >
                      {data.isActive ? (
                        <CheckCircle className="w-2.5 h-2.5" />
                      ) : (
                        <XCircle className="w-2.5 h-2.5" />
                      )}
                      {data.isActive ? "Active" : "Inactive"}
                    </Badge>
                  </div>
                )}
              </div>

              {data && (
                <p className="mt-1.5 text-xs text-t4 bg-surface-3 border border-gs-line rounded px-2 py-1 inline-block">
                  {data.category}
                </p>
              )}
            </div>
          </div>
        </DialogHeader>

        {/* ── Body ── */}
        <ScrollArea className="h-[calc(95vh-130px)]">
          {isLoading ? (
            <div className="flex items-center justify-center p-12">
              <div className="text-center space-y-2">
                <Loader2 className="h-8 w-8 animate-spin text-brand mx-auto" />
                <p className="text-sm text-t3">Loading tariff details…</p>
              </div>
            </div>
          ) : error ? (
            <div className="flex flex-col items-center justify-center p-12 text-center gap-3">
              <XCircle className="h-12 w-12 text-destructive" />
              <p className="text-destructive font-semibold text-sm">
                Error loading tariff
              </p>
              <p className="text-xs text-t4">
                {(error as { message?: string }).message ?? "Please try again."}
              </p>
            </div>
          ) : data ? (
            <div className="p-4 space-y-4">

              {/* ── Premium summary strip ── */}
              <div className="grid grid-cols-3 gap-3">
                {[
                  {
                    label: "Own Damage Basic",
                    value: `৳ ${formatMoney(data.ownDpBasic)}`,
                    icon: <DollarSign className="w-4 h-4 text-brand" />,
                  },
                  {
                    label: "Full Insurance Value",
                    value: formatRate(data.fullInsValue),
                    icon: <Percent className="w-4 h-4 text-brand" />,
                  },
                  {
                    label: "Act Liability",
                    value: `৳ ${formatMoney(data.actLiability)}`,
                    icon: <ShieldCheck className="w-4 h-4 text-brand" />,
                  },
                ].map(({ label, value, icon }) => (
                  <div
                    key={label}
                    className="rounded-gs border border-gs-line bg-surface-2/50 p-3 flex flex-col gap-1"
                  >
                    <div className="flex items-center gap-1.5 text-t3 mb-1">
                      {icon}
                      <span className="text-[10px] font-semibold uppercase tracking-wide">
                        {label}
                      </span>
                    </div>
                    <p className="text-lg font-bold text-t1">{value}</p>
                  </div>
                ))}
              </div>

              {/* ── Risk rates ── */}
              <InfoCard
                title="Risk Rates"
                icon={<FlameKindling className="h-3.5 w-3.5" />}
              >
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                  <RateMetric
                    label="Fire"
                    value={data.fire}
                    icon={<FlameKindling className="w-3.5 h-3.5" />}
                  />
                  <RateMetric
                    label="Theft"
                    value={data.theft}
                    icon={<ShieldCheck className="w-3.5 h-3.5" />}
                  />
                  <RateMetric
                    label="Cyclone"
                    value={data.cyclone}
                    icon={<Wind className="w-3.5 h-3.5" />}
                  />
                  <RateMetric
                    label="Earthquake"
                    value={data.earthquake}
                    icon={<Mountain className="w-3.5 h-3.5" />}
                  />
                </div>
              </InfoCard>

              {/* ── Classification & Audit ── */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <InfoCard
                  title="Vehicle Classification"
                  icon={<Car className="h-3.5 w-3.5" />}
                >
                  <div className="space-y-3">
                    <InfoRow label="Tariff Type" value={data.tariffType} />
                    <Separator className="bg-gs-line" />
                    <InfoRow label="Vehicle Group" value={data.groupOfVehicle} />
                    <Separator className="bg-gs-line" />
                    <InfoRow label="Vehicle Type" value={data.typeOfVehicle} />
                    <Separator className="bg-gs-line" />
                    <InfoRow label="Category / CC" value={data.category} />
                  </div>
                </InfoCard>

                <InfoCard
                  title="Audit Trail"
                  icon={<Calendar className="h-3.5 w-3.5" />}
                >
                  <div className="space-y-3">
                    <InfoRow
                      icon={<Calendar className="w-3.5 h-3.5 text-gs-green" />}
                      label="Created"
                      value={
                        <div>
                          <p className="text-sm text-t1">{formatDate(data.createdAt)}</p>
                          {data.createdBy && (
                            <p className="text-[10px] text-t4">by {data.createdBy}</p>
                          )}
                        </div>
                      }
                    />
                    <Separator className="bg-gs-line" />
                    <InfoRow
                      icon={<Calendar className="w-3.5 h-3.5 text-t3" />}
                      label="Last Updated"
                      value={
                        <div>
                          <p className="text-sm text-t1">{formatDate(data.updatedAt)}</p>
                          {data.updatedBy && (
                            <p className="text-[10px] text-t4">by {data.updatedBy}</p>
                          )}
                        </div>
                      }
                    />
                  </div>
                </InfoCard>
              </div>
            </div>
          ) : null}
        </ScrollArea>
      </DialogContent>
    </Dialog>
  );
}