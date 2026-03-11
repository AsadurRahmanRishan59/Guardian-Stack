// features/masteradmin/tariff/motor/components/MotorTariffForm.tsx
"use client";

import { useEffect } from "react";
import { useForm, useWatch, Resolver } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { Loader2, AlertCircle, Info } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Separator } from "@/components/ui/separator";

import {
  motorTariffSchema,
  MotorTariffFormValues,
} from "../motor.tariff.schema";
import type { MotorTariffFullDTO } from "../motor.tariff.types";
import { useMotorHierarchy } from "../motor.tariff.react-query";

interface MotorTariffFormProps {
  onSubmit: (data: MotorTariffFormValues) => void;
  isPending?: boolean;
  initialData?: MotorTariffFullDTO | null;
  mode?: "create" | "edit";
  serverError?: string | null;
}

// ── Rate input field ──────────────────────────────────────────────────────────

function RateField({
  form,
  name,
  label,
  unit = "%",
  placeholder = "0.00",
}: {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  form: any;
  name: keyof MotorTariffFormValues;
  label: string;
  unit?: string;
  placeholder?: string;
}) {
  return (
    <FormField
      control={form.control}
      name={name}
      render={({ field }) => (
        <FormItem>
          <FormLabel className="text-xs text-t2 font-medium">{label}</FormLabel>
          <FormControl>
            <div className="relative">
              <Input
                {...field}
                type="number"
                step="0.01"
                min="0"
                placeholder={placeholder}
                value={field.value ?? ""}
                onChange={(e) => field.onChange(e.target.value)}
                className="pr-8 bg-surface border-gs-line text-t1 focus:border-brand focus:ring-brand/20 h-9 text-sm"
              />
              <span className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[10px] text-t4 font-mono pointer-events-none">
                {unit}
              </span>
            </div>
          </FormControl>
          <FormMessage className="text-[10px]" />
        </FormItem>
      )}
    />
  );
}

// ── Main form ─────────────────────────────────────────────────────────────────

export function MotorTariffForm({
  onSubmit,
  isPending = false,
  initialData,
  mode = "create",
  serverError,
}: MotorTariffFormProps) {
  const form = useForm<MotorTariffFormValues>({
    resolver: zodResolver(motorTariffSchema) as Resolver<MotorTariffFormValues>,
    defaultValues: {
      tariffType: undefined,
      groupOfVehicle: "",
      typeOfVehicle: "",
      category: "",
      ownDpBasic: 0,
      fullInsValue: 0,
      actLiability: 0,
      fire: 0,
      theft: 0,
      cyclone: 0,
      earthquake: 0,
      isActive: true,
    },
  });

  // Populate form in edit mode
  useEffect(() => {
    if (!initialData || mode !== "edit") return;
    form.reset({
      tariffType: initialData.tariffType,
      groupOfVehicle: initialData.groupOfVehicle,
      typeOfVehicle: initialData.typeOfVehicle,
      category: initialData.category,
      ownDpBasic: Number(initialData.ownDpBasic),
      fullInsValue: Number(initialData.fullInsValue),
      actLiability: Number(initialData.actLiability),
      fire: Number(initialData.fire),
      theft: Number(initialData.theft),
      cyclone: Number(initialData.cyclone),
      earthquake: Number(initialData.earthquake),
      isActive: initialData.isActive,
    });
  }, [initialData, mode, form]);

  // Watch values for cascading dropdowns
  const selectedTariffType = useWatch({ control: form.control, name: "tariffType" });
  const selectedGroup = useWatch({ control: form.control, name: "groupOfVehicle" });
  const selectedType = useWatch({ control: form.control, name: "typeOfVehicle" });

  // Hierarchy queries
  const { options: tariffTypes = [], isLoading: typesLoading } = useMotorHierarchy(
    "tariffType",
    {}
  );
  const { options: groups = [], isLoading: groupsLoading } = useMotorHierarchy(
    "groupOfVehicle",
    { tariffType: selectedTariffType }
  );
  const { options: vehicleTypes = [], isLoading: vehicleTypesLoading } =
    useMotorHierarchy("typeOfVehicle", {
      tariffType: selectedTariffType,
      groupOfVehicle: selectedGroup,
    });
  const { options: categories = [], isLoading: categoriesLoading } =
    useMotorHierarchy("category", {
      tariffType: selectedTariffType,
      groupOfVehicle: selectedGroup,
      typeOfVehicle: selectedType,
    });

  // Reset dependent fields when parent changes
  const handleTariffTypeChange = (val: string) => {
    form.setValue("tariffType", val as MotorTariffFormValues["tariffType"]);
    form.setValue("groupOfVehicle", "");
    form.setValue("typeOfVehicle", "");
    form.setValue("category", "");
  };

  const handleGroupChange = (val: string) => {
    form.setValue("groupOfVehicle", val);
    form.setValue("typeOfVehicle", "");
    form.setValue("category", "");
  };

  const handleVehicleTypeChange = (val: string) => {
    form.setValue("typeOfVehicle", val);
    form.setValue("category", "");
  };

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-5">
        {/* Server error */}
        {serverError && (
          <Alert variant="destructive" className="border-destructive/30 bg-destructive/10 py-2.5">
            <AlertCircle className="h-3.5 w-3.5" />
            <AlertDescription className="text-xs">{serverError}</AlertDescription>
          </Alert>
        )}

        {/* ── Section: Vehicle Classification ── */}
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <Info className="h-3.5 w-3.5 text-brand" />
            <h3 className="text-[10px] font-bold uppercase tracking-widest text-t3">
              Vehicle Classification
            </h3>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {/* Tariff Type */}
            <FormField
              control={form.control}
              name="tariffType"
              render={({ field }) => (
                <FormItem>
                  <FormLabel className="text-xs text-t2 font-medium">
                    Tariff Type <span className="text-destructive">*</span>
                  </FormLabel>
                  <Select
                    value={field.value ?? ""}
                    onValueChange={handleTariffTypeChange}
                    disabled={typesLoading}
                  >
                    <FormControl>
                      <SelectTrigger className="bg-surface border-gs-line text-t1 h-9 text-sm focus:ring-brand/20">
                        <SelectValue placeholder={typesLoading ? "Loading…" : "Select tariff type"} />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent className="bg-surface-card border-gs-line">
                      {tariffTypes.map((t: string) => (
                        <SelectItem key={t} value={t} className="text-sm text-t1">
                          {t}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <FormMessage className="text-[10px]" />
                </FormItem>
              )}
            />

            {/* Group of Vehicle */}
            <FormField
              control={form.control}
              name="groupOfVehicle"
              render={({ field }) => (
                <FormItem>
                  <FormLabel className="text-xs text-t2 font-medium">
                    Group of Vehicle <span className="text-destructive">*</span>
                  </FormLabel>
                  <Select
                    value={field.value ?? ""}
                    onValueChange={handleGroupChange}
                    disabled={!selectedTariffType || groupsLoading}
                  >
                    <FormControl>
                      <SelectTrigger className="bg-surface border-gs-line text-t1 h-9 text-sm focus:ring-brand/20">
                        <SelectValue
                          placeholder={
                            !selectedTariffType
                              ? "Select tariff type first"
                              : groupsLoading
                              ? "Loading…"
                              : "Select group"
                          }
                        />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent className="bg-surface-card border-gs-line">
                      {groups.map((g: string) => (
                        <SelectItem key={g} value={g} className="text-sm text-t1">
                          {g}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <FormMessage className="text-[10px]" />
                </FormItem>
              )}
            />

            {/* Type of Vehicle */}
            <FormField
              control={form.control}
              name="typeOfVehicle"
              render={({ field }) => (
                <FormItem>
                  <FormLabel className="text-xs text-t2 font-medium">
                    Type of Vehicle <span className="text-destructive">*</span>
                  </FormLabel>
                  <Select
                    value={field.value ?? ""}
                    onValueChange={handleVehicleTypeChange}
                    disabled={!selectedGroup || vehicleTypesLoading}
                  >
                    <FormControl>
                      <SelectTrigger className="bg-surface border-gs-line text-t1 h-9 text-sm focus:ring-brand/20">
                        <SelectValue
                          placeholder={
                            !selectedGroup
                              ? "Select group first"
                              : vehicleTypesLoading
                              ? "Loading…"
                              : "Select vehicle type"
                          }
                        />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent className="bg-surface-card border-gs-line">
                      {vehicleTypes.map((vt: string) => (
                        <SelectItem key={vt} value={vt} className="text-sm text-t1">
                          {vt}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <FormMessage className="text-[10px]" />
                </FormItem>
              )}
            />

            {/* Category */}
            <FormField
              control={form.control}
              name="category"
              render={({ field }) => (
                <FormItem>
                  <FormLabel className="text-xs text-t2 font-medium">
                    Category / CC Range <span className="text-destructive">*</span>
                  </FormLabel>
                  <Select
                    value={field.value ?? ""}
                    onValueChange={(val) => form.setValue("category", val)}
                    disabled={!selectedType || categoriesLoading}
                  >
                    <FormControl>
                      <SelectTrigger className="bg-surface border-gs-line text-t1 h-9 text-sm focus:ring-brand/20">
                        <SelectValue
                          placeholder={
                            !selectedType
                              ? "Select vehicle type first"
                              : categoriesLoading
                              ? "Loading…"
                              : "Select category"
                          }
                        />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent className="bg-surface-card border-gs-line">
                      {categories.map((c: string) => (
                        <SelectItem key={c} value={c} className="text-sm text-t1">
                          {c}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <FormMessage className="text-[10px]" />
                </FormItem>
              )}
            />
          </div>
        </div>

        <Separator className="bg-gs-line" />

        {/* ── Section: Premium & Liability ── */}
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <Info className="h-3.5 w-3.5 text-brand" />
            <h3 className="text-[10px] font-bold uppercase tracking-widest text-t3">
              Premium & Liability
            </h3>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <RateField
              form={form}
              name="ownDpBasic"
              label="Own DP Basic Premium *"
              unit="BDT"
              placeholder="0.00"
            />
            <RateField
              form={form}
              name="fullInsValue"
              label="Full Insurance Value *"
              unit="%"
              placeholder="0.00"
            />
            <RateField
              form={form}
              name="actLiability"
              label="Act Liability *"
              unit="BDT"
              placeholder="0.00"
            />
          </div>
        </div>

        <Separator className="bg-gs-line" />

        {/* ── Section: Peril Rates ── */}
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <Info className="h-3.5 w-3.5 text-brand" />
            <h3 className="text-[10px] font-bold uppercase tracking-widest text-t3">
              Peril Rates (%)
            </h3>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <RateField form={form} name="fire" label="Fire *" />
            <RateField form={form} name="theft" label="Theft *" />
            <RateField form={form} name="cyclone" label="Cyclone *" />
            <RateField form={form} name="earthquake" label="Earthquake *" />
          </div>
        </div>

        <Separator className="bg-gs-line" />

        {/* ── Status ── */}
        <FormField
          control={form.control}
          name="isActive"
          render={({ field }) => (
            <FormItem className="flex items-center justify-between rounded-gs border border-gs-line bg-surface-2/50 px-4 py-3">
              <div>
                <FormLabel className="text-sm font-medium text-t1">
                  Active Status
                </FormLabel>
                <p className="text-[10px] text-t4 mt-0.5">
                  Inactive tariffs are hidden from rate calculations
                </p>
              </div>
              <FormControl>
                <Switch
                  checked={field.value}
                  onCheckedChange={field.onChange}
                  className="data-[state=checked]:bg-brand"
                />
              </FormControl>
            </FormItem>
          )}
        />

        {/* ── Actions ── */}
        <div className="flex items-center justify-end gap-2 pt-1">
          <Button
            type="submit"
            disabled={isPending}
            className="bg-brand hover:bg-brand-hover text-white gap-2 h-9"
          >
            {isPending && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
            {mode === "create" ? "Create Tariff" : "Save Changes"}
          </Button>
        </div>
      </form>
    </Form>
  );
}