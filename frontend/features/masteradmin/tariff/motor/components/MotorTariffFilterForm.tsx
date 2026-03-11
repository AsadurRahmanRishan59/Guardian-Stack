"use client";

import { FC, useEffect } from "react";
import { useForm, useWatch } from "react-hook-form";
import { RotateCcw, Search, Loader2 } from "lucide-react";

import {
  Form,
  FormField,
  FormItem,
  FormLabel,
  FormControl,
} from "@/components/ui/form";
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { useMotorHierarchy } from "../motor.tariff.react-query";
import { MotorTariffSearchCriteria } from "../motor.tariff.types";

// Simple TS Type instead of Zod
export type MotorTariffFilterValues = {
  tariffKey?: number;
  tariffType?: string;
  groupOfVehicle?: string;
  typeOfVehicle?: string;
  category?: string;
  isActive?: boolean;
  page: number;
  size: number;
  sortBy: string;
  sortDirection: "asc" | "desc";
};

interface MotorTariffFilterFormProps {
  onSubmit: (data: MotorTariffSearchCriteria) => void;
  defaultValues?: Partial<MotorTariffSearchCriteria>;
}

const fieldLabel = "text-xs font-semibold text-t3 uppercase tracking-wide mb-1";

/**
 * SelectTrigger: fixed height, selected text truncates with ellipsis.
 * `[&>span]:truncate` ensures the inner Radix value span clips cleanly.
 */
const triggerCls =
  "h-8 text-sm bg-surface border-gs-line text-t1 w-full overflow-hidden " +
  "focus-visible:ring-brand disabled:opacity-50 " +
  "[&>span]:truncate [&>span]:block [&>span]:overflow-hidden [&>span]:max-w-full";

/**
 * SelectContent: match trigger width on small screens, cap at 400 px on large ones.
 * `w-[var(--radix-select-trigger-width)]` is set by Radix automatically.
 */
const contentCls =
  "w-[var(--radix-select-trigger-width)] min-w-[160px] max-w-[400px]";

/** SelectItem: allow long text to wrap. */
const itemCls =
  "whitespace-normal leading-snug py-2 min-h-[2.5rem] " +
  "flex items-center justify-start text-left cursor-pointer";

const MotorTariffFilterForm: FC<MotorTariffFilterFormProps> = ({
  onSubmit,
  defaultValues = {},
}) => {
  const form = useForm<MotorTariffSearchCriteria>({
    defaultValues: {
      page: 0,
      size: 10,
      sortBy: "tariffKey",
      sortDirection: "asc",
      ...defaultValues,
    },
  });

  const watched = useWatch({ control: form.control });

  // ── Hierarchy Data ──────────────────────────────────────────────────────────
  const { options: tariffTypes, isLoading: loadingTypes } =
    useMotorHierarchy("tariffType", {});
  const { options: vehicleGroups, isLoading: loadingGroups } =
    useMotorHierarchy("groupOfVehicle", { tariffType: watched.tariffType });
  const { options: vehicleTypes, isLoading: loadingVehTypes } =
    useMotorHierarchy("typeOfVehicle", {
      tariffType: watched.tariffType,
      groupOfVehicle: watched.groupOfVehicle,
    });
  const { options: categories, isLoading: loadingCats } =
    useMotorHierarchy("category", {
      tariffType: watched.tariffType,
      groupOfVehicle: watched.groupOfVehicle,
      typeOfVehicle: watched.typeOfVehicle,
    });

  // ── Cascading Reset Logic ───────────────────────────────────────────────────
  useEffect(() => {
    form.setValue("groupOfVehicle", undefined);
    form.setValue("typeOfVehicle", undefined);
    form.setValue("category", undefined);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [watched.tariffType]);

  useEffect(() => {
    form.setValue("typeOfVehicle", undefined);
    form.setValue("category", undefined);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [watched.groupOfVehicle]);

  useEffect(() => {
    form.setValue("category", undefined);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [watched.typeOfVehicle]);

  const handleClear = () => {
    const cleared: MotorTariffSearchCriteria = {
      page: 0,
      size: 10,
      sortBy: "tariffKey",
      sortDirection: "asc",
    };
    form.reset(cleared);
    onSubmit(cleared);
  };

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-3">

          {/* Tariff Type */}
          <FormField
            control={form.control}
            name="tariffType"
            render={({ field }) => (
              <FormItem className="space-y-1 min-w-0">
                <FormLabel className={fieldLabel}>Tariff Type</FormLabel>
                <Select
                  onValueChange={(v) => field.onChange(v === "all" ? undefined : v)}
                  value={field.value ?? "all"}
                >
                  <FormControl>
                    <SelectTrigger className={triggerCls}>
                      {loadingTypes ? (
                        <Loader2 className="w-3 h-3 animate-spin" />
                      ) : (
                        <SelectValue placeholder="All" />
                      )}
                    </SelectTrigger>
                  </FormControl>
                  <SelectContent className={contentCls}>
                    <SelectItem value="all" className={itemCls}>All Types</SelectItem>
                    {tariffTypes.map((t) => (
                      <SelectItem key={t} value={t} className={itemCls}>{t}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </FormItem>
            )}
          />

          {/* Vehicle Group */}
          <FormField
            control={form.control}
            name="groupOfVehicle"
            render={({ field }) => (
              <FormItem className="space-y-1 min-w-0">
                <FormLabel className={fieldLabel}>Vehicle Group</FormLabel>
                <Select
                  disabled={!watched.tariffType}
                  onValueChange={(v) => field.onChange(v === "all" ? undefined : v)}
                  value={field.value ?? "all"}
                >
                  <FormControl>
                    <SelectTrigger className={triggerCls}>
                      {loadingGroups ? (
                        <Loader2 className="w-3 h-3 animate-spin" />
                      ) : (
                        <SelectValue placeholder="Select Type First" />
                      )}
                    </SelectTrigger>
                  </FormControl>
                  <SelectContent className={contentCls}>
                    <SelectItem value="all" className={itemCls}>All Groups</SelectItem>
                    {vehicleGroups.map((g) => (
                      <SelectItem key={g} value={g} className={itemCls}>{g}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </FormItem>
            )}
          />

          {/* Vehicle Type */}
          <FormField
            control={form.control}
            name="typeOfVehicle"
            render={({ field }) => (
              <FormItem className="space-y-1 min-w-0">
                <FormLabel className={fieldLabel}>Vehicle Type</FormLabel>
                <Select
                  disabled={!watched.groupOfVehicle}
                  onValueChange={(v) => field.onChange(v === "all" ? undefined : v)}
                  value={field.value ?? "all"}
                >
                  <FormControl>
                    <SelectTrigger className={triggerCls}>
                      {loadingVehTypes ? (
                        <Loader2 className="w-3 h-3 animate-spin" />
                      ) : (
                        <SelectValue placeholder="Select Group First" />
                      )}
                    </SelectTrigger>
                  </FormControl>
                  <SelectContent className={contentCls}>
                    <SelectItem value="all" className={itemCls}>All Vehicle Types</SelectItem>
                    {vehicleTypes.map((vt) => (
                      <SelectItem key={vt} value={vt} className={itemCls}>{vt}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </FormItem>
            )}
          />

          {/* Category / CC Range */}
          <FormField
            control={form.control}
            name="category"
            render={({ field }) => (
              <FormItem className="space-y-1 min-w-0">
                <FormLabel className={fieldLabel}>Category / CC Range</FormLabel>
                <Select
                  disabled={!watched.typeOfVehicle}
                  onValueChange={(v) => field.onChange(v === "all" ? undefined : v)}
                  value={field.value ?? "all"}
                >
                  <FormControl>
                    <SelectTrigger className={triggerCls}>
                      {loadingCats ? (
                        <Loader2 className="w-3 h-3 animate-spin" />
                      ) : (
                        <SelectValue placeholder="Select Type First" />
                      )}
                    </SelectTrigger>
                  </FormControl>
                  <SelectContent className={contentCls}>
                    <SelectItem value="all" className={itemCls}>All Categories</SelectItem>
                    {categories.map((c) => (
                      <SelectItem key={c} value={c} className={itemCls}>{c}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </FormItem>
            )}
          />

          {/* Is Active */}
          <FormField
            control={form.control}
            name="isActive"
            render={({ field }) => (
              <FormItem className="space-y-1 min-w-0">
                <FormLabel className={fieldLabel}>Status</FormLabel>
                <Select
                  onValueChange={(v) =>
                    field.onChange(v === "all" ? undefined : v === "true")
                  }
                  value={
                    field.value === undefined
                      ? "all"
                      : field.value
                      ? "true"
                      : "false"
                  }
                >
                  <FormControl>
                    <SelectTrigger className={triggerCls}>
                      <SelectValue placeholder="All Statuses" />
                    </SelectTrigger>
                  </FormControl>
                  <SelectContent className={contentCls}>
                    <SelectItem value="all" className={itemCls}>All Statuses</SelectItem>
                    <SelectItem value="true" className={itemCls}>Active</SelectItem>
                    <SelectItem value="false" className={itemCls}>Inactive</SelectItem>
                  </SelectContent>
                </Select>
              </FormItem>
            )}
          />
        </div>

        <div className="flex justify-end gap-2 pt-1 border-t border-gs-line">
          <Button
            type="button"
            variant="ghost"
            size="sm"
            onClick={handleClear}
            className="h-8 gap-1.5"
          >
            <RotateCcw className="w-3.5 h-3.5" /> Clear All
          </Button>
          <Button
            type="submit"
            size="sm"
            className="h-8 bg-brand hover:bg-brand-hover text-white gap-1.5 px-6"
          >
            <Search className="w-3.5 h-3.5" /> Apply
          </Button>
        </div>
      </form>
    </Form>
  );
};

export default MotorTariffFilterForm;