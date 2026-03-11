// features/masteradmin/tariff/motor/MotorTariffFilterForm.tsx
"use client";

import { FC, useEffect } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { RotateCcw, Search } from "lucide-react";

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
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";

import {
  motorTariffFilterSchema,
  MotorTariffFilterFormValues,
} from "../motor.tariff.schema";

interface MotorTariffFilterFormProps {
  onSubmit: (data: MotorTariffFilterFormValues) => void;
  defaultValues?: Partial<MotorTariffFilterFormValues>;
}

const fieldLabel = "text-xs font-semibold text-t3 uppercase tracking-wide mb-1";
const control =
  "h-8 text-sm bg-surface border-gs-line text-t1 placeholder:text-t4 focus-visible:ring-brand focus-visible:border-brand transition-colors";

const TARIFF_TYPES = ["Private Vehicle", "Motor Cycle", "Commercial Vehicle"];

const MotorTariffFilterForm: FC<MotorTariffFilterFormProps> = ({
  onSubmit,
  defaultValues = {},
}) => {
  const form = useForm<MotorTariffFilterFormValues>({
    resolver: zodResolver(motorTariffFilterSchema),
    defaultValues: {
      page: 0,
      size: 10,
      sortBy: "tariffKey",
      sortDirection: "asc",
      ...defaultValues,
    },
  });

  const defaultValuesKey = JSON.stringify(defaultValues);
  useEffect(() => {
    form.reset({
      page: 0,
      size: 10,
      sortBy: "tariffKey",
      sortDirection: "asc",
      ...defaultValues,
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [defaultValuesKey]);

  const handleSubmit = (data: MotorTariffFilterFormValues) => {
    onSubmit({ ...data, page: 0 });
  };

  const handleClear = () => {
    const cleared: MotorTariffFilterFormValues = {
      page: 0,
      size: defaultValues.size ?? 10,
      sortBy: "tariffKey",
      sortDirection: "asc",
    };
    form.reset(cleared);
    onSubmit(cleared);
  };

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(handleSubmit)} className="space-y-4">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">

          {/* Tariff Key */}
          <FormField
            control={form.control}
            name="tariffKey"
            render={({ field }) => (
              <FormItem className="space-y-1">
                <FormLabel className={fieldLabel}>Tariff ID</FormLabel>
                <FormControl>
                  <Input
                    {...field}
                    type="number"
                    min={1}
                    placeholder="Search by ID…"
                    className={control}
                    value={field.value ?? ""}
                    onChange={(e) =>
                      field.onChange(
                        e.target.value === "" ? undefined : Number(e.target.value)
                      )
                    }
                  />
                </FormControl>
              </FormItem>
            )}
          />

          {/* Tariff Type */}
          <FormField
            control={form.control}
            name="tariffType"
            render={({ field }) => (
              <FormItem className="space-y-1">
                <FormLabel className={fieldLabel}>Tariff Type</FormLabel>
                <FormControl>
                  <Select
                    onValueChange={(v) =>
                      field.onChange(v === "all" ? undefined : v)
                    }
                    value={field.value ?? "all"}
                  >
                    <SelectTrigger className={control}>
                      <SelectValue placeholder="All types" />
                    </SelectTrigger>
                    <SelectContent className="bg-surface-card border-gs-line">
                      <SelectItem value="all" className="text-sm text-t3 focus:bg-surface-2">
                        All types
                      </SelectItem>
                      {TARIFF_TYPES.map((t) => (
                        <SelectItem
                          key={t}
                          value={t}
                          className="text-sm text-t2 focus:bg-surface-2 focus:text-t1"
                        >
                          {t}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </FormControl>
              </FormItem>
            )}
          />

          {/* Group of Vehicle */}
          <FormField
            control={form.control}
            name="groupOfVehicle"
            render={({ field }) => (
              <FormItem className="space-y-1">
                <FormLabel className={fieldLabel}>Vehicle Group</FormLabel>
                <FormControl>
                  <Input
                    {...field}
                    placeholder="Search vehicle group…"
                    className={control}
                    value={field.value ?? ""}
                    onChange={(e) =>
                      field.onChange(e.target.value || undefined)
                    }
                  />
                </FormControl>
              </FormItem>
            )}
          />

          {/* Type of Vehicle */}
          <FormField
            control={form.control}
            name="typeOfVehicle"
            render={({ field }) => (
              <FormItem className="space-y-1">
                <FormLabel className={fieldLabel}>Vehicle Type</FormLabel>
                <FormControl>
                  <Input
                    {...field}
                    placeholder="Search vehicle type…"
                    className={control}
                    value={field.value ?? ""}
                    onChange={(e) =>
                      field.onChange(e.target.value || undefined)
                    }
                  />
                </FormControl>
              </FormItem>
            )}
          />

          {/* Category */}
          <FormField
            control={form.control}
            name="category"
            render={({ field }) => (
              <FormItem className="space-y-1">
                <FormLabel className={fieldLabel}>Category / CC</FormLabel>
                <FormControl>
                  <Input
                    {...field}
                    placeholder="Search category…"
                    className={control}
                    value={field.value ?? ""}
                    onChange={(e) =>
                      field.onChange(e.target.value || undefined)
                    }
                  />
                </FormControl>
              </FormItem>
            )}
          />

          {/* Active Status */}
          <FormField
            control={form.control}
            name="isActive"
            render={({ field }) => (
              <FormItem className="space-y-1">
                <FormLabel className={fieldLabel}>Status</FormLabel>
                <FormControl>
                  <Select
                    onValueChange={(v) =>
                      field.onChange(
                        v === "all" ? undefined : v === "true"
                      )
                    }
                    value={
                      field.value === undefined ? "all" : String(field.value)
                    }
                  >
                    <SelectTrigger className={control}>
                      <SelectValue placeholder="All statuses" />
                    </SelectTrigger>
                    <SelectContent className="bg-surface-card border-gs-line">
                      <SelectItem value="all" className="text-sm text-t3 focus:bg-surface-2">
                        All statuses
                      </SelectItem>
                      <SelectItem value="true" className="text-sm text-t2 focus:bg-surface-2 focus:text-t1">
                        Active
                      </SelectItem>
                      <SelectItem value="false" className="text-sm text-t2 focus:bg-surface-2 focus:text-t1">
                        Inactive
                      </SelectItem>
                    </SelectContent>
                  </Select>
                </FormControl>
              </FormItem>
            )}
          />
        </div>

        {/* Actions */}
        <div className="flex justify-end gap-2 pt-1 border-t border-gs-line">
          <Button
            type="button"
            variant="ghost"
            size="sm"
            onClick={handleClear}
            className="h-8 text-t3 hover:text-t1 hover:bg-surface-3 gap-1.5"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            Clear All
          </Button>
          <Button
            type="submit"
            size="sm"
            className="h-8 bg-brand hover:bg-brand-hover text-white gap-1.5"
          >
            <Search className="w-3.5 h-3.5" />
            Apply Filters
          </Button>
        </div>
      </form>
    </Form>
  );
};

export default MotorTariffFilterForm;