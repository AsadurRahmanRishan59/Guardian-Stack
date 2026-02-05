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
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";

import { Loader2 } from "lucide-react";
import { ComboboxSelect } from "@/components/combobox-select";
import {
  MasterAdminUserViewFilterFormData,
  masterAdminUserViewFilterSchema,
} from "../user.schema";
import { MasterAdminUserViewFilterOptions } from "../user.types";

interface MasterAdminUserViewFilterFormProps {
  onSubmit: (data: MasterAdminUserViewFilterFormData) => void;
  defaultValues?: Partial<MasterAdminUserViewFilterFormData>;
  filterOptions: MasterAdminUserViewFilterOptions;
  currentSearch?: string;
}

export const MasterAdminUserViewFilterForm: FC<MasterAdminUserViewFilterFormProps> = ({
  onSubmit,
  defaultValues = {},
  filterOptions
}) => {
  const { 
    activeStatuses, 
    accountLockStatuses,
    accountExpireStatuses,
    credentialExpireStatuses,
    signUpMethods, 
    roles 
  } = filterOptions;

  const form = useForm<MasterAdminUserViewFilterFormData>({
    resolver: zodResolver(masterAdminUserViewFilterSchema),
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

  const handleSubmit = (data: MasterAdminUserViewFilterFormData) => {
    const cleaned = {
      ...data,
      username: data.username?.trim() || undefined,
      email: data.email?.trim() || undefined,
      enabled: typeof data.enabled === "boolean" ? data.enabled : undefined,
      accountLocked: typeof data.accountLocked === "boolean" ? data.accountLocked : undefined,
      accountExpired: typeof data.accountExpired === "boolean" ? data.accountExpired : undefined,
      credentialExpired: typeof data.credentialExpired === "boolean" ? data.credentialExpired : undefined,
      signUpMethod: data.signUpMethod || undefined,
      roleIds: data.roleIds && data.roleIds.length > 0 ? data.roleIds : undefined,
      page: 0, // Always reset to page 0
      size: data.size || 10,
      sortBy: data.sortBy || "username",
      sortDirection: data.sortDirection || "asc",
    };

    onSubmit(cleaned);
  };

  const handleClear = () => {
    const clearedData = {
      username: undefined,
      email: undefined,
      enabled: undefined,
      accountLocked: undefined,
      accountExpired: undefined,
      credentialExpired: undefined,
      signUpMethod: undefined,
      roleIds: undefined,
      page: 0,
      size: defaultValues.size || 10,
      sortBy: "username" as MasterAdminUserViewFilterFormData["sortBy"],
      sortDirection: "asc" as MasterAdminUserViewFilterFormData["sortDirection"],
    };

    form.reset(clearedData);
    onSubmit(clearedData);
  };

  return (
    <Form {...form}>
      <form
        onSubmit={form.handleSubmit(handleSubmit)}
        className="grid gap-3 md:grid-cols-3 items-end mb-4 text-sm"
      >
        {/* Username */}
        <FormField
          control={form.control}
          name="username"
          render={({ field }) => (
            <FormItem className="space-y-1">
              <FormLabel className="text-sm">Username</FormLabel>
              <FormControl>
                <Input
                  {...field}
                  placeholder="Search username"
                  className="h-8"
                />
              </FormControl>
            </FormItem>
          )}
        />

        {/* Email */}
        <FormField
          control={form.control}
          name="email"
          render={({ field }) => (
            <FormItem className="space-y-1">
              <FormLabel className="text-sm">Email</FormLabel>
              <FormControl>
                <Input
                  {...field}
                  type="email"
                  placeholder="Search email"
                  className="h-8"
                />
              </FormControl>
            </FormItem>
          )}
        />

        {/* Roles */}
        <FormField
          control={form.control}
          name="roleIds"
          render={({ field }) => (
            <FormItem className="space-y-1">
              <FormLabel className="text-sm">Roles</FormLabel>
              <FormControl>
                <ComboboxSelect
                  items={roles}
                  value={field.value}
                  onChange={field.onChange}
                  placeholder="Select roles"
                  displayField="roleName"
                  valueField="roleId"
                  multiple={true}
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
            <FormItem className="space-y-1">
              <FormLabel className="text-sm">Sign Up Method</FormLabel>
              <FormControl>
                <Select
                  onValueChange={(val) => field.onChange(val === "all" ? undefined : val)}
                  value={field.value ?? "all"}
                >
                  <SelectTrigger className="h-8">
                    <SelectValue placeholder="All methods" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All methods</SelectItem>
                    {signUpMethods.map((method) => (
                      <SelectItem key={method} value={method}>
                        {method}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </FormControl>
            </FormItem>
          )}
        />

        {/* Enabled Status */}
        <FormField
          control={form.control}
          name="enabled"
          render={({ field }) => (
            <FormItem className="space-y-1">
              <FormLabel className="text-sm">Account Status</FormLabel>
              <FormControl>
                <Select
                  onValueChange={(val) =>
                    field.onChange(val === "all" ? undefined : val === "true")
                  }
                  value={
                    field.value === undefined ? "all" : field.value.toString()
                  }
                >
                  <SelectTrigger className="h-8">
                    <SelectValue placeholder="All statuses" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All statuses</SelectItem>
                    {activeStatuses.map((status) => (
                      <SelectItem key={status.toString()} value={status.toString()}>
                        {status ? "Active" : "Inactive"}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </FormControl>
            </FormItem>
          )}
        />

        {/* Account Locked */}
        <FormField
          control={form.control}
          name="accountLocked"
          render={({ field }) => (
            <FormItem className="space-y-1">
              <FormLabel className="text-sm">Account Lock</FormLabel>
              <FormControl>
                <Select
                  onValueChange={(val) =>
                    field.onChange(val === "all" ? undefined : val === "true")
                  }
                  value={
                    field.value === undefined ? "all" : field.value.toString()
                  }
                >
                  <SelectTrigger className="h-8">
                    <SelectValue placeholder="All" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All</SelectItem>
                    {accountLockStatuses.map((status) => (
                      <SelectItem key={status.toString()} value={status.toString()}>
                        {status ? "Locked" : "Unlocked"}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </FormControl>
            </FormItem>
          )}
        />

        {/* Account Expired */}
        <FormField
          control={form.control}
          name="accountExpired"
          render={({ field }) => (
            <FormItem className="space-y-1">
              <FormLabel className="text-sm">Account Expiry</FormLabel>
              <FormControl>
                <Select
                  onValueChange={(val) =>
                    field.onChange(val === "all" ? undefined : val === "true")
                  }
                  value={
                    field.value === undefined ? "all" : field.value.toString()
                  }
                >
                  <SelectTrigger className="h-8">
                    <SelectValue placeholder="All" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All</SelectItem>
                    {accountExpireStatuses.map((status) => (
                      <SelectItem key={status.toString()} value={status.toString()}>
                        {status ? "Expired" : "Valid"}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </FormControl>
            </FormItem>
          )}
        />

        {/* Credential Expired */}
        <FormField
          control={form.control}
          name="credentialExpired"
          render={({ field }) => (
            <FormItem className="space-y-1">
              <FormLabel className="text-sm">Credential Expiry</FormLabel>
              <FormControl>
                <Select
                  onValueChange={(val) =>
                    field.onChange(val === "all" ? undefined : val === "true")
                  }
                  value={
                    field.value === undefined ? "all" : field.value.toString()
                  }
                >
                  <SelectTrigger className="h-8">
                    <SelectValue placeholder="All" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All</SelectItem>
                    {credentialExpireStatuses.map((status) => (
                      <SelectItem key={status.toString()} value={status.toString()}>
                        {status ? "Expired" : "Valid"}
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
            Clear All
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