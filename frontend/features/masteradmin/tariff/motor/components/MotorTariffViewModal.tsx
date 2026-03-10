"use client";

import React from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogBody,
  DialogClose,
} from "@/components/ui/custom-dialog";
import { Badge } from "@/components/ui/badge";
import {
  Car,
  Shield,
  DollarSign,
  Zap,
  Flame,
  CloudRain,
  Building,
  CheckCircle,
  XCircle,
  Loader2,
  FileText,
  Clock,
} from "lucide-react";
import { useGetMotorTariffByTariffKey } from "../motor.tariff.react-query";

export interface MotorTariffType {
  // Define based on your actual type structure
  id: number;
  name: string;
}

export interface MotorTariffGroupOfVehicle {
  // Define based on your actual group structure
  id: number;
  name: string;
}

export interface MotorTariff {
  tariffKey: number;
  tariffType: MotorTariffType;
  groupOfVehicle: MotorTariffGroupOfVehicle;
  typeOfVehicle: string;
  category: string;
  ownDpBasic: number;
  fullInsValue: number;
  actLiability: number;
  fire: number;
  theft: number;
  cyclone: number;
  earthquake: number;
  others: number;
  isActive: boolean;
  createdAt: string;
  lastUpdatedAt: string;
}

interface MotorTariffModalProps {
  tariffKey: number;
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
}

export default function MotorTariffViewModal({
  tariffKey,
  open = false,
  onOpenChange = () => {},
}: MotorTariffModalProps) {
  const {
    data: motorTariffData,
    isLoading,
    error,
  } = useGetMotorTariffByTariffKey(open && tariffKey ? tariffKey : undefined);

  const formatDateTime = (dateString?: string) => {
    if (!dateString) return "";
    return new Date(dateString).toLocaleString("en-GB", {
      day: "2-digit",
      month: "2-digit",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  const formatCurrency = (amount: number) => {
    return new Intl.NumberFormat("en-US", {
      style: "currency",
      currency: "BDT",
      minimumFractionDigits: 2,
    }).format(amount);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="full" className="max-h-[90vh] overflow-y-auto">
        <DialogClose />

        {isLoading ? (
          <DialogBody>
            <div className="flex items-center justify-center p-8">
              <Loader2 className="h-8 w-8 animate-spin text-primary" />
              <span className="ml-3 text-lg">
                Loading motor tariff details...
              </span>
            </div>
          </DialogBody>
        ) : error ? (
          <DialogBody>
            <div className="flex items-center justify-center p-8 text-center">
              <p className="text-red-500 text-lg mb-2">
                Error loading motor tariff details
              </p>
              <p className="text-sm text-muted-foreground">
                {error.message || "Please try again later"}
              </p>
            </div>
          </DialogBody>
        ) : motorTariffData ? (
          <>
            <DialogHeader>
              <div className="flex items-start gap-4">
                <Car className="h-6 w-6 text-primary mt-1 flex-shrink-0" />
                <div className="flex-grow">
                  <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-3">
                    <div>
                      <DialogTitle className="text-2xl font-bold">
                        {motorTariffData.typeOfVehicle}
                      </DialogTitle>
                      <p className="text-sm text-muted-foreground mt-1">
                        Tariff Key: #{motorTariffData.tariffKey}
                      </p>
                      <p className="text-sm text-muted-foreground">
                        Category: {motorTariffData.category}
                      </p>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      <Badge variant="secondary">MOTOR TARIFF</Badge>
                      <Badge
                        variant={
                          motorTariffData.isActive ? "default" : "destructive"
                        }
                        className={
                          motorTariffData.isActive
                            ? "bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 hover:bg-emerald-500/20"
                            : "bg-red-500/10 text-red-700 dark:text-red-300 hover:bg-red-500/20"
                        }
                      >
                        {motorTariffData.isActive ? (
                          <CheckCircle className="w-3 h-3 mr-1" />
                        ) : (
                          <XCircle className="w-3 h-3 mr-1" />
                        )}
                        {motorTariffData.isActive ? "Active" : "Inactive"}
                      </Badge>
                    </div>
                  </div>

                  <div className="flex flex-wrap items-center gap-2 mt-3">
                    <Badge variant="outline">
                      <Building className="w-3 h-3 mr-1" />
                      {motorTariffData.groupOfVehicle}
                    </Badge>
                    <Badge variant="outline">
                      <FileText className="w-3 h-3 mr-1" />
                      {motorTariffData.tariffType}
                    </Badge>
                  </div>
                </div>
              </div>
            </DialogHeader>

            <DialogBody>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="space-y-6">
                  <Section
                    title="Basic Information"
                    icon={<Car className="h-4 w-4" />}
                  >
                    <Info
                      label="Vehicle Type"
                      value={motorTariffData.typeOfVehicle}
                    />
                    <Info label="Category" value={motorTariffData.category} />
                    <Info
                      label="Group of Vehicle"
                      value={motorTariffData.groupOfVehicle}
                    />
                    <Info
                      label="Tariff Type"
                      value={motorTariffData.tariffType}
                    />
                  </Section>

                  <Section
                    title="Basic Coverage"
                    icon={<Shield className="h-4 w-4" />}
                  >
                    <div className="bg-blue-50 dark:bg-blue-900/30 p-4 rounded-lg border border-blue-200 dark:border-blue-800">
                      <Info
                        label="Own Damage Basic"
                        value={formatCurrency(motorTariffData.ownDpBasic)}
                        className="font-medium text-lg"
                      />
                      <Info
                        label="Full Insurance Value"
                        value={formatCurrency(motorTariffData.fullInsValue)}
                        className="font-medium"
                      />
                      <Info
                        label="Act Liability"
                        value={formatCurrency(motorTariffData.actLiability)}
                        className="font-medium"
                      />
                    </div>
                  </Section>
                </div>

                <div className="space-y-6">
                  <Section
                    title="Risk Coverage Premiums"
                    icon={<DollarSign className="h-4 w-4" />}
                  >
                    <div className="grid grid-cols-2 gap-4">
                      <div className="bg-orange-50 dark:bg-orange-900/30 p-3 rounded-lg border border-orange-200 dark:border-orange-800">
                        <div className="flex items-center gap-2 mb-2">
                          <Flame className="w-4 h-4 text-orange-600" />
                          <span className="text-sm font-medium">Fire</span>
                        </div>
                        <p className="text-lg font-semibold">
                          {formatCurrency(motorTariffData.fire)}
                        </p>
                      </div>

                      <div className="bg-purple-50 dark:bg-purple-900/30 p-3 rounded-lg border border-purple-200 dark:border-purple-800">
                        <div className="flex items-center gap-2 mb-2">
                          <Shield className="w-4 h-4 text-purple-600" />
                          <span className="text-sm font-medium">Theft</span>
                        </div>
                        <p className="text-lg font-semibold">
                          {formatCurrency(motorTariffData.theft)}
                        </p>
                      </div>

                      <div className="bg-cyan-50 dark:bg-cyan-900/30 p-3 rounded-lg border border-cyan-200 dark:border-cyan-800">
                        <div className="flex items-center gap-2 mb-2">
                          <CloudRain className="w-4 h-4 text-cyan-600" />
                          <span className="text-sm font-medium">Cyclone</span>
                        </div>
                        <p className="text-lg font-semibold">
                          {formatCurrency(motorTariffData.cyclone)}
                        </p>
                      </div>

                      <div className="bg-amber-50 dark:bg-amber-900/30 p-3 rounded-lg border border-amber-200 dark:border-amber-800">
                        <div className="flex items-center gap-2 mb-2">
                          <Zap className="w-4 h-4 text-amber-600" />
                          <span className="text-sm font-medium">
                            Earthquake
                          </span>
                        </div>
                        <p className="text-lg font-semibold">
                          {formatCurrency(motorTariffData.earthquake)}
                        </p>
                      </div>
                    </div>

                    <div className="bg-gray-50 dark:bg-gray-900/30 p-4 rounded-lg border border-gray-200 dark:border-gray-800 mt-4">
                      <Info
                        label="Others"
                        value={formatCurrency(motorTariffData.others)}
                        className="font-medium text-lg"
                      />
                    </div>
                  </Section>

                  <Section
                    title="System Information"
                    icon={<Clock className="h-4 w-4" />}
                  >
                    <Info
                      label="Created At"
                      value={formatDateTime(motorTariffData.createdAt)}
                    />
                    <Info
                      label="Last Updated"
                      value={formatDateTime(motorTariffData.lastUpdatedAt)}
                    />
                  </Section>
                </div>
              </div>
            </DialogBody>
          </>
        ) : null}
      </DialogContent>
    </Dialog>
  );
}

function Section({
  title,
  children,
  icon,
}: {
  title: string;
  children: React.ReactNode;
  icon?: React.ReactNode;
}) {
  return (
    <div>
      <div className="flex items-center gap-2 mb-3">
        {icon && <span className="text-muted-foreground">{icon}</span>}
        <h3 className="font-semibold text-base text-foreground border-b border-border pb-1 w-full">
          {title}
        </h3>
      </div>
      <div className="space-y-3 pl-1">{children}</div>
    </div>
  );
}

function Info({
  label,
  value,
  className = "",
}: {
  label: string;
  value: React.ReactNode;
  className?: string;
}) {
  return (
    <div className="flex flex-col">
      <p className="text-xs text-muted-foreground">{label}</p>
      <p className={`text-sm ${className}`}>
        {value || (
          <span className="text-muted-foreground/70">Not provided</span>
        )}
      </p>
    </div>
  );
}
