"use client";

import { useEffect } from "react";
import { useForm, Resolver, Control } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { Loader2, Car, ShieldCheck } from "lucide-react";
import { toast } from "sonner";

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
import { Separator } from "@/components/ui/separator";
import { Skeleton } from "@/components/ui/skeleton";

import {
  motorTariffSchema,
  MotorTariffFormValues,
} from "../motor.tariff.schema";
import {
  useCreateMotorTariff,
  useUpdateMotorTariff,
  useMotorTariffById,
} from "../motor.tariff.react-query";
import { isServerError } from "@/lib/api/error-handling";
import { TariffType } from "../motor.tariff.types";

interface MotorTariffFormProps {
  tariffKey?: number; // If present, we are in EDIT mode
  onSuccess: () => void;
}

interface NumericFieldProps {
  control: Control<MotorTariffFormValues>;
  name: keyof MotorTariffFormValues;
  label: string;
  unit?: string;
}

export function MotorTariffForm({
  tariffKey,
  onSuccess,
}: MotorTariffFormProps) {
  const isEditMode = !!tariffKey;

  // Mutations & Queries
  const { data: tariff, isLoading: isFetching } = useMotorTariffById(tariffKey);
  const createMutation = useCreateMotorTariff();
  const updateMutation = useUpdateMotorTariff();

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
    mode: "onChange",
  });

  const { control, handleSubmit, setError, reset } = form;

  useEffect(() => {
    if (isEditMode && tariff) {
      reset(tariff);
    }
  }, [isEditMode, tariff, reset]);

  const onSubmit = async (data: MotorTariffFormValues) => {
    try {
      if (isEditMode && tariffKey) {
        await updateMutation.mutateAsync({ tariffKey, dto: data });
      } else {
        await createMutation.mutateAsync(data);
      }
      reset();
      onSuccess();
    } catch (error) {
      if (
        isServerError(error) &&
        typeof error.data === "object" &&
        error.data !== null
      ) {
        const dataObj = error.data as Record<string, string>;
        Object.entries(dataObj).forEach(([field, message]) => {
          setError(field as keyof MotorTariffFormValues, {
            type: "server",
            message,
          });
        });
      } else {
        toast.error(`Failed to ${isEditMode ? "update" : "create"} tariff`);
      }
    }
  };

  if (isEditMode && isFetching) {
    return (
      <div className="space-y-4 p-4">
        <Skeleton className="h-8 w-1/3" />
        <div className="grid grid-cols-2 gap-4">
          <Skeleton className="h-10" />
          <Skeleton className="h-10" />
        </div>
        <Skeleton className="h-32 w-full" />
      </div>
    );
  }

  return (
    <Form {...form}>
      <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
        {/* --- Vehicle Classification --- */}
        <div className="space-y-4">
          <div className="flex items-center gap-2">
            <Car className="h-4 w-4 text-brand" />
            <h3 className="text-[10px] font-bold uppercase tracking-wider text-t3">
              Vehicle Classification
            </h3>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <FormField
              control={control}
              name="tariffType"
              render={({ field }) => (
                <FormItem>
                  <FormLabel className="text-xs font-medium">
                    Tariff Type *
                  </FormLabel>

                  <Select
                    key={field.value ? `loaded-${field.value}` : "loading"}
                    onValueChange={field.onChange}
                    defaultValue={field.value}
                    value={field.value}
                  >
                    <FormControl>
                      <SelectTrigger className="h-9">
                        <SelectValue placeholder="Select type" />
                      </SelectTrigger>
                    </FormControl>

                    <SelectContent>
                      {Object.values(TariffType).map((v) => (
                        <SelectItem key={v} value={v}>
                          {v}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>

                  <FormMessage className="text-[10px]" />
                </FormItem>
              )}
            />

            <FormField
              control={control}
              name="groupOfVehicle"
              render={({ field }) => (
                <FormItem>
                  <FormLabel className="text-xs font-medium">
                    Vehicle Group *
                  </FormLabel>
                  <FormControl>
                    <Input {...field} className="h-9" />
                  </FormControl>
                  <FormMessage className="text-[10px]" />
                </FormItem>
              )}
            />
            <FormField
              control={control}
              name="typeOfVehicle"
              render={({ field }) => (
                <FormItem>
                  <FormLabel className="text-xs font-medium">
                    Vehicle Type *
                  </FormLabel>
                  <FormControl>
                    <Input {...field} className="h-9" />
                  </FormControl>
                  <FormMessage className="text-[10px]" />
                </FormItem>
              )}
            />
            <FormField
              control={control}
              name="category"
              render={({ field }) => (
                <FormItem>
                  <FormLabel className="text-xs font-medium">
                    Category / CC Range *
                  </FormLabel>
                  <FormControl>
                    <Input {...field} className="h-9" />
                  </FormControl>
                  <FormMessage className="text-[10px]" />
                </FormItem>
              )}
            />
          </div>
        </div>

        <Separator />

        {/* --- Rates Section --- */}
        <div className="space-y-4">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-brand" />
            <h3 className="text-[10px] font-bold uppercase tracking-wider text-t3">
              Premium & Peril Rates
            </h3>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <NumericField
              control={control}
              name="ownDpBasic"
              label="Basic Premium"
              unit="BDT"
            />
            <NumericField
              control={control}
              name="fullInsValue"
              label="Full Ins. Value"
              unit="%"
            />
            <NumericField
              control={control}
              name="actLiability"
              label="Act Liability"
              unit="BDT"
            />
          </div>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 p-3 rounded-lg bg-surface-2/30 border border-gs-line/40">
            <NumericField control={control} name="fire" label="Fire" />
            <NumericField control={control} name="theft" label="Theft" />
            <NumericField control={control} name="cyclone" label="Cyclone" />
            <NumericField
              control={control}
              name="earthquake"
              label="Earthquake"
            />
          </div>
        </div>

        <div className="flex items-center justify-between p-4 rounded-md border bg-surface/50">
          <p className="text-sm font-semibold">Active Status</p>
          <FormField
            control={control}
            name="isActive"
            render={({ field }) => (
              <Switch
                checked={field.value as boolean}
                onCheckedChange={field.onChange}
              />
            )}
          />
        </div>

        <div className="flex justify-end pt-2">
          <Button
            type="submit"
            disabled={createMutation.isPending || updateMutation.isPending}
            className="bg-brand hover:bg-brand-hover text-white h-9 px-12"
          >
            {(createMutation.isPending || updateMutation.isPending) && (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            )}
            {isEditMode ? "Update Tariff" : "Create Tariff"}
          </Button>
        </div>
      </form>
    </Form>
  );
}

function NumericField({ control, name, label, unit = "%" }: NumericFieldProps) {
  return (
    <FormField
      control={control}
      name={name}
      render={({ field }) => (
        <FormItem>
          <FormLabel className="text-xs font-medium">{label}</FormLabel>
          <div className="relative">
            <Input
              type="number"
              step="0.01"
              className="h-9 pr-7"
              {...field}
              value={(field.value as number) ?? 0}
              onChange={(e) =>
                field.onChange(
                  e.target.value === "" ? 0 : Number(e.target.value),
                )
              }
            />
            <span className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[9px] font-bold text-t4">
              {unit}
            </span>
          </div>
          <FormMessage className="text-[10px]" />
        </FormItem>
      )}
    />
  );
}
