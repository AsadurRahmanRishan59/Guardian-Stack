// features/admin/user/components/MasterAdminUserViewFilterForm.tsx
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
import { Loader2, RotateCcw, Search } from "lucide-react";
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

// Shared field label style
const fieldLabelClass = "text-xs font-semibold text-t3 uppercase tracking-wide mb-1";
// Shared input/select height
const controlClass = "h-8 text-sm bg-surface border-gs-line text-t1 placeholder:text-t4 focus-visible:ring-brand focus-visible:border-brand transition-colors";

export const MasterAdminUserViewFilterForm: FC<MasterAdminUserViewFilterFormProps> = ({
  onSubmit,
  defaultValues = {},
  filterOptions,
}) => {
  const {
    activeStatuses,
    accountLockStatuses,
    accountExpireStatuses,
    credentialExpireStatuses,
    signUpMethods,
    roles,
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
    onSubmit({
      ...data,
      username: data.username?.trim() || undefined,
      email: data.email?.trim() || undefined,
      enabled: typeof data.enabled === "boolean" ? data.enabled : undefined,
      accountLocked:
        typeof data.accountLocked === "boolean" ? data.accountLocked : undefined,
      accountExpired:
        typeof data.accountExpired === "boolean" ? data.accountExpired : undefined,
      credentialExpired:
        typeof data.credentialExpired === "boolean"
          ? data.credentialExpired
          : undefined,
      signUpMethod: data.signUpMethod || undefined,
      roleIds:
        data.roleIds && data.roleIds.length > 0 ? data.roleIds : undefined,
      page: 0,
      size: data.size || 10,
      sortBy: data.sortBy || "username",
      sortDirection: data.sortDirection || "asc",
    });
  };

  const handleClear = () => {
    const cleared: MasterAdminUserViewFilterFormData = {
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
      sortBy: "username",
      sortDirection: "asc",
    };
    form.reset(cleared);
    onSubmit(cleared);
  };

  return (
    <Form {...form}>
      <form
        onSubmit={form.handleSubmit(handleSubmit)}
        className="space-y-4"
      >
        {/* Grid of filters */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">

          {/* Username */}
          <FormField
            control={form.control}
            name="username"
            render={({ field }) => (
              <FormItem className="space-y-1">
                <FormLabel className={fieldLabelClass}>Username</FormLabel>
                <FormControl>
                  <Input
                    {...field}
                    placeholder="Search username…"
                    className={controlClass}
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
                <FormLabel className={fieldLabelClass}>Email</FormLabel>
                <FormControl>
                  <Input
                    {...field}
                    type="email"
                    placeholder="Search email…"
                    className={controlClass}
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
                <FormLabel className={fieldLabelClass}>Roles</FormLabel>
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
                <FormLabel className={fieldLabelClass}>Sign Up Method</FormLabel>
                <FormControl>
                  <Select
                    onValueChange={(val) =>
                      field.onChange(val === "all" ? undefined : val)
                    }
                    value={field.value ?? "all"}
                  >
                    <SelectTrigger className={controlClass}>
                      <SelectValue placeholder="All methods" />
                    </SelectTrigger>
                    <SelectContent className="bg-surface-card border-gs-line">
                      <SelectItem value="all" className="text-sm text-t3 focus:bg-surface-2">All methods</SelectItem>
                      {signUpMethods.map((method) => (
                        <SelectItem key={method} value={method} className="text-sm text-t2 focus:bg-surface-2 focus:text-t1">
                          {method}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </FormControl>
              </FormItem>
            )}
          />

          {/* Account Status */}
          <FormField
            control={form.control}
            name="enabled"
            render={({ field }) => (
              <FormItem className="space-y-1">
                <FormLabel className={fieldLabelClass}>Account Status</FormLabel>
                <FormControl>
                  <Select
                    onValueChange={(val) =>
                      field.onChange(val === "all" ? undefined : val === "true")
                    }
                    value={field.value === undefined ? "all" : field.value.toString()}
                  >
                    <SelectTrigger className={controlClass}>
                      <SelectValue placeholder="All statuses" />
                    </SelectTrigger>
                    <SelectContent className="bg-surface-card border-gs-line">
                      <SelectItem value="all" className="text-sm text-t3 focus:bg-surface-2">All statuses</SelectItem>
                      {activeStatuses.map((status) => (
                        <SelectItem key={status.toString()} value={status.toString()} className="text-sm text-t2 focus:bg-surface-2 focus:text-t1">
                          {status ? "Active" : "Inactive"}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </FormControl>
              </FormItem>
            )}
          />

          {/* Account Lock */}
          <FormField
            control={form.control}
            name="accountLocked"
            render={({ field }) => (
              <FormItem className="space-y-1">
                <FormLabel className={fieldLabelClass}>Account Lock</FormLabel>
                <FormControl>
                  <Select
                    onValueChange={(val) =>
                      field.onChange(val === "all" ? undefined : val === "true")
                    }
                    value={field.value === undefined ? "all" : field.value.toString()}
                  >
                    <SelectTrigger className={controlClass}>
                      <SelectValue placeholder="All" />
                    </SelectTrigger>
                    <SelectContent className="bg-surface-card border-gs-line">
                      <SelectItem value="all" className="text-sm text-t3 focus:bg-surface-2">All</SelectItem>
                      {accountLockStatuses.map((status) => (
                        <SelectItem key={status.toString()} value={status.toString()} className="text-sm text-t2 focus:bg-surface-2 focus:text-t1">
                          {status ? "Locked" : "Unlocked"}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </FormControl>
              </FormItem>
            )}
          />

          {/* Account Expiry */}
          <FormField
            control={form.control}
            name="accountExpired"
            render={({ field }) => (
              <FormItem className="space-y-1">
                <FormLabel className={fieldLabelClass}>Account Expiry</FormLabel>
                <FormControl>
                  <Select
                    onValueChange={(val) =>
                      field.onChange(val === "all" ? undefined : val === "true")
                    }
                    value={field.value === undefined ? "all" : field.value.toString()}
                  >
                    <SelectTrigger className={controlClass}>
                      <SelectValue placeholder="All" />
                    </SelectTrigger>
                    <SelectContent className="bg-surface-card border-gs-line">
                      <SelectItem value="all" className="text-sm text-t3 focus:bg-surface-2">All</SelectItem>
                      {accountExpireStatuses.map((status) => (
                        <SelectItem key={status.toString()} value={status.toString()} className="text-sm text-t2 focus:bg-surface-2 focus:text-t1">
                          {status ? "Expired" : "Valid"}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </FormControl>
              </FormItem>
            )}
          />

          {/* Credential Expiry */}
          <FormField
            control={form.control}
            name="credentialExpired"
            render={({ field }) => (
              <FormItem className="space-y-1">
                <FormLabel className={fieldLabelClass}>Credential Expiry</FormLabel>
                <FormControl>
                  <Select
                    onValueChange={(val) =>
                      field.onChange(val === "all" ? undefined : val === "true")
                    }
                    value={field.value === undefined ? "all" : field.value.toString()}
                  >
                    <SelectTrigger className={controlClass}>
                      <SelectValue placeholder="All" />
                    </SelectTrigger>
                    <SelectContent className="bg-surface-card border-gs-line">
                      <SelectItem value="all" className="text-sm text-t3 focus:bg-surface-2">All</SelectItem>
                      {credentialExpireStatuses.map((status) => (
                        <SelectItem key={status.toString()} value={status.toString()} className="text-sm text-t2 focus:bg-surface-2 focus:text-t1">
                          {status ? "Expired" : "Valid"}
                        </SelectItem>
                      ))}
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
            disabled={form.formState.isSubmitting}
            className="h-8 bg-brand hover:bg-brand-hover text-white gap-1.5"
          >
            {form.formState.isSubmitting ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Search className="w-3.5 h-3.5" />
            )}
            Apply Filters
          </Button>
        </div>
      </form>
    </Form>
  );
};