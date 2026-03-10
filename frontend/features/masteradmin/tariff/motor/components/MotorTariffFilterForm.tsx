"use client";

import { FC, useEffect } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import {
  MotorTariffFilterFormValues,
  motorTariffFilterSchema,
} from "../motor.tariff.schema";

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
import { Loader2 } from "lucide-react";
import { useMotorHierarchyLevel } from "../motor.tariff.react-query";
import { ComboboxSelect } from "@/components/table/combobox-select";

interface MotorTariffFilterFormProps {
  onSubmit: (data: MotorTariffFilterFormValues) => void;
  defaultValues?: Partial<MotorTariffFilterFormValues>;
  currentSearch?: string;
}

export const MotorTariffFilterForm: FC<MotorTariffFilterFormProps> = ({
  onSubmit,
  defaultValues = {},
  currentSearch,
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

  // Watch form values to handle dependencies
  const watchedTariffType = form.watch("tariffType");
  const watchedGroupOfVehicle = form.watch("groupOfVehicle");
  const watchedTypeOfVehicle = form.watch("typeOfVehicle");

  const { data: tariffTypesResponse, isLoading: loadingTariffTypes,error:tariffTypeError } =
    useMotorHierarchyLevel("tariffType", {});
  const tariffTypes = tariffTypesResponse?.data ?? [];

  const { data: groupOfVehiclesResponse, isLoading: loadingGroupOfVehicles,error:groupError } =
    useMotorHierarchyLevel("groupOfVehicle", {
      tariffType: watchedTariffType,
    });
  const groupOfVehicles = groupOfVehiclesResponse?.data ?? [];

  const { data: typeOfVehiclesResponse, isLoading: loadingTypeOfVehicles,error:typeError } =
    useMotorHierarchyLevel("typeOfVehicle", {
      tariffType: watchedTariffType,
      groupOfVehicle: watchedGroupOfVehicle,
    });
  const typeOfVehicles = typeOfVehiclesResponse?.data ?? [];

  const { data: categoriesResponse, isLoading: loadingCategories,error:catError } =
    useMotorHierarchyLevel("category", {
      tariffType: watchedTariffType,
      groupOfVehicle: watchedGroupOfVehicle,
      typeOfVehicle: watchedTypeOfVehicle,
    });
  const categories = categoriesResponse?.data ?? [];

  useEffect(() => {
    form.reset({
      page: 0,
      size: 10,
      sortBy: "tariffKey",
      sortDirection: "asc",
      ...defaultValues,
    });
  }, [defaultValues, form]);

  // Reset dependent fields on parent change
  useEffect(() => {
    form.setValue("groupOfVehicle", undefined, { shouldDirty: false });
    form.setValue("typeOfVehicle", undefined, { shouldDirty: false });
    form.setValue("category", undefined, { shouldDirty: false });
  }, [watchedTariffType, form]);

  useEffect(() => {
    form.setValue("typeOfVehicle", undefined, { shouldDirty: false });
    form.setValue("category", undefined, { shouldDirty: false });
  }, [watchedGroupOfVehicle, form]);

  useEffect(() => {
    form.setValue("category", undefined, { shouldDirty: false });
  }, [watchedTypeOfVehicle, form]);

  const handleSubmit = (data: MotorTariffFilterFormValues) => {
    const cleaned = {
      ...data,
      tariffKey: currentSearch?.trim()
        ? parseInt(currentSearch.trim())
        : undefined,
      tariffType: data.tariffType || undefined,
      groupOfVehicle: data.groupOfVehicle || undefined,
      typeOfVehicle: data.typeOfVehicle || undefined,
      category: data.category || undefined,
      isActive: typeof data.isActive === "boolean" ? data.isActive : undefined,
      page: 0, // Always reset to page 0
      size: data.size || 10,
      sortBy: data.sortBy || "tariffKey",
      sortDirection: data.sortDirection || "asc",
    };

    onSubmit(cleaned);
  };

  const handleClear = () => {
    const clearedData: Partial<MotorTariffFilterFormValues> = {
      tariffKey: undefined,
      tariffType: undefined,
      groupOfVehicle: undefined,
      typeOfVehicle: undefined,
      category: undefined,
      isActive: undefined,
      page: 0,
      size: defaultValues.size || 10,
      sortBy: "tariffKey",
      sortDirection: "asc",
    };

    form.reset(clearedData);
    onSubmit(clearedData);
  };

  return (
    <Form {...form}>
      <form
        onSubmit={form.handleSubmit(handleSubmit)}
        className="grid gap-2 grid-cols-1 md:grid-cols-3 items-end mb-4 text-sm"
      >
        {/* Tariff Type */}
        <FormField
          control={form.control}
          name="tariffType"
          render={({ field }) => (
            <FormItem className="space-y-1 md:col-span-2">
              <FormLabel>Tariff Type</FormLabel>
              <FormControl>
                <ComboboxSelect
                  items={tariffTypes.map((t) => ({ label: t, value: t }))}
                  value={field.value} // string | undefined
                  onChange={(val) => field.onChange(val || undefined)} // (string | undefined) => void
                  placeholder="Select tariff type"
                  error={tariffTypeError?.message}
                  loading={loadingTariffTypes}
                  displayField="label"
                  valueField="value"
                  tableMode
                  columns={[
                    { key: "label", header: "Tariff Type", width: "full" },
                  ]}
                />
              </FormControl>
            </FormItem>
          )}
        />

        {/* Status */}
        <FormField
          control={form.control}
          name="isActive"
          render={({ field }) => (
            <FormItem className="">
              <FormLabel className="text-sm">Status</FormLabel>
              <FormControl>
                <Select
                  onValueChange={(val) =>
                    field.onChange(val === "" ? undefined : val === "true")
                  }
                  value={
                    field.value === undefined ? "" : field.value.toString()
                  }
                >
                  <SelectTrigger className="h-8 bg-background border border-input hover:bg-accent hover:text-accent-foreground">
                    <SelectValue placeholder="Select status" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="true">Active</SelectItem>
                    <SelectItem value="false">Inactive</SelectItem>
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
            <FormItem className="space-y-1 md:col-span-3">
              <FormLabel>Group of Vehicle</FormLabel>
              <FormControl>
                <ComboboxSelect
                  items={groupOfVehicles.map((g) => ({ label: g, value: g }))}
                  value={field.value}
                  onChange={(val) => field.onChange(val || undefined)}
                  placeholder="Select group of vehicle"
                  displayField="label"
                  valueField="value"
                  loading={loadingGroupOfVehicles}
                  error={groupError?.message}
                  disabled={!watchedTariffType}
                  tableMode
                  columns={[
                    {
                      key: "label",
                      header: "Group of Vehicle",
                      width: "full",
                    },
                  ]}
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
            <FormItem className="space-y-1 md:col-span-3">
              <FormLabel>Type of Vehicle</FormLabel>
              <FormControl>
                <ComboboxSelect
                  items={typeOfVehicles.map((t) => ({ label: t, value: t }))}
                  value={field.value}
                  onChange={(val) => field.onChange(val || undefined)}
                  placeholder="Select type of vehicle"
                  displayField="label"
                  valueField="value"
                  loading={loadingTypeOfVehicles}
                  error={typeError?.message}
                  disabled={!watchedTariffType || !watchedGroupOfVehicle}
                  tableMode
                  columns={[
                    { key: "label", header: "Type of Vehicle", width: "full" },
                  ]}
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
            <FormItem className="space-y-1 md:col-span-3">
              <FormLabel>Category</FormLabel>
              <FormControl>
                <ComboboxSelect
                  items={categories.map((c) => ({ label: c, value: c }))}
                  value={field.value}
                  onChange={(val) => field.onChange(val || undefined)}
                  placeholder="Select category"
                  displayField="label"
                  valueField="value"
                  loading={loadingCategories}
                  error={catError?.message}
                  disabled={
                    !watchedTariffType ||
                    !watchedGroupOfVehicle ||
                    !watchedTypeOfVehicle
                  }
                  tableMode
                  columns={[
                    { key: "label", header: "Category", width: "full" },
                  ]}
                />
              </FormControl>
            </FormItem>
          )}
        />

        {/* Actions */}
        <div className="md:col-span-3 lg:col-span-4 flex justify-end gap-2 mt-2">
          <Button type="button" variant="ghost" size="sm" onClick={handleClear}>
            Clear
          </Button>
          <Button
            type="submit"
            size="sm"
            disabled={form.formState.isSubmitting}
          >
            {form.formState.isSubmitting && (
              <Loader2 className="w-4 h-4 animate-spin mr-2" />
            )}
            Apply Filters
          </Button>
        </div>
      </form>
    </Form>
  );
};
