"use client";

import { FC, useEffect } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";

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

import {  Loader2 } from "lucide-react";
import { ComboboxSelect } from "@/components/combobox-select";
import {
  AdminUserViewFilterFormData,
  adminUserViewFilterSchema,
} from "../user.schema";
import { AdminUserViewFilterOptions } from "../user.types";

interface AdminUserViewFilterFormProps {
  onSubmit: (data: AdminUserViewFilterFormData) => void;
  defaultValues?: Partial<AdminUserViewFilterFormData>;
  filterOptions: AdminUserViewFilterOptions;
  currentSearch?: string;
}

export const AdminUserViewFilterForm: FC<AdminUserViewFilterFormProps> = ({
  onSubmit,
  defaultValues = {},
  filterOptions,
  currentSearch,
}) => {
  const { activeStatuses,signUpMethods,roles  } = filterOptions;

  const form = useForm<AdminUserViewFilterFormData>({
    resolver: zodResolver(adminUserViewFilterSchema),
    defaultValues: {
      page: 0,
      size: 10,
      sortBy: "username",
      sortDirection: "asc",
      ...defaultValues,
    },
  });

  useEffect(() => {
    form.reset({
      page: 0,
      size: 10,
      sortBy: "username",
      sortDirection: "asc",
      ...defaultValues,
    });
  }, [defaultValues, form]);

  const handleSubmit = (data: AdminUserViewFilterFormData) => {
    const cleaned = {
      ...data,
      username: currentSearch?.trim() || undefined,
      enabled: typeof data.enabled === "boolean" ? data.enabled : undefined,
      isTwoFactorEnabled:
        typeof data.isTwoFactorEnabled === "boolean"
          ? data.isTwoFactorEnabled
          : undefined,
      signUpMethod: data.signUpMethod || undefined,
      roleId: data.roleId || undefined,
      page: 0, // Always reset to page 0
      size: data.size || 10,
      sortBy: data.sortBy || "username",
      sortDirection: data.sortDirection || "asc",
    };

    onSubmit(cleaned);
  };

  const handleClear = () => {
    const clearedData = {
      username: currentSearch?.trim() || undefined,
      enabled: undefined,
      isTwoFactorEnabled: undefined,
      signUpMethod: undefined,
      roleId: undefined,
      page: 0,
      size: defaultValues.size,
      sortBy: "username" as AdminUserViewFilterFormData["sortBy"],
      sortDirection: "asc" as AdminUserViewFilterFormData["sortDirection"],
    };

    form.reset(clearedData);
    onSubmit(clearedData);
  };

  return (
    <Form {...form}>
      <form
        onSubmit={form.handleSubmit(handleSubmit)}
        className="grid gap-2 md:grid-cols-3 items-end mb-4 text-sm"
      >
        {/* User */}
        <FormField
          control={form.control}
          name="roleId"
          render={({ field }) => (
            <FormItem className="space-y-1">
              <FormLabel className="text-sm">Roles</FormLabel>
              <FormControl>
                <ComboboxSelect
                  items={roles}
                  value={field.value}
                  onChange={field.onChange}
                  placeholder="Select role"
                  displayField="roleName"
                  valueField="roleId"
                />
              </FormControl>
            </FormItem>
          )}
        />

        {/* Sign Up Method */}
        <FormField
          control={form.control}
          name="signUpMethod"
          render={({ field }) => (
            <FormItem>
              <FormLabel className="text-sm">Sign Up Method</FormLabel>
              <FormControl>
                <Select
                  onValueChange={field.onChange}
                  value={field.value ?? ""}
                >
                  <SelectTrigger className="h-8">
                    <SelectValue placeholder="Select" />
                  </SelectTrigger>
                  <SelectContent>
                    {signUpMethods.map((g) => (
                      <SelectItem key={g} value={g}>
                        {g}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </FormControl>
            </FormItem>
          )}
        />

        {/* Status */}
        <FormField
          control={form.control}
          name="enabled"
          render={({ field }) => (
            <FormItem>
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
                  <SelectTrigger className="h-8">
                    <SelectValue placeholder="Select status" />
                  </SelectTrigger>
                  <SelectContent>
                    {activeStatuses.map((s) => (
                      <SelectItem key={s.toString()} value={s.toString()}>
                        {s ? "Active" : "Inactive"}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </FormControl>
            </FormItem>
          )}
        />

        {/* Actions */}
        <div className="md:col-span-3 flex justify-end gap-2 mt-2">
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
