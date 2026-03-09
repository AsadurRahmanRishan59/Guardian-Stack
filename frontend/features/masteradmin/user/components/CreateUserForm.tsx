// features/admin/user/CreateUserForm.tsx
"use client";

import { useForm, useWatch } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import {
  createMasterAdminUserSchema,
  MasterAdminUserFormData,
} from "../user.schema";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import {
  MasterAdminUserUpdateRequestDTO,
  MasterAdminUserCreateRequestDTO,
} from "../user.types";
import {
  useCreateUser,
  useGetUserById,
  useUpdateUser,
} from "../user.react.query";
import { Loader2, Info, AlertCircle, ShieldCheck, CheckCircle2 } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { useMemo, useEffect } from "react";
import { Badge } from "@/components/ui/badge";
import { useQueryGetRoles } from "../../role/role.react.query";
import { cn } from "@/lib/utils";

function dateInputToIso(value?: string | null): string | null {
  if (!value) return null;
  return `${value}T00:00:00`;
}
function isoToDateInput(value?: string | null): string {
  if (!value) return "";
  return value.split("T")[0];
}

interface CreateUserFormProps {
  onSuccess?: () => void;
  userId?: number;
}

export function CreateUserForm({ onSuccess, userId }: CreateUserFormProps) {
  const isEditMode = !!userId;

  const { data: editData, isLoading: userDataLoading, error: userDataError } =
    useGetUserById(isEditMode ? userId : undefined);

  const { roles, isLoading: rolesLoading, error: rolesError } = useQueryGetRoles();

  const { mutate: createUser, isPending: isCreating } = useCreateUser();
  const { mutate: updateUser, isPending: isUpdating } = useUpdateUser();
  const isPending = isEditMode ? isUpdating : isCreating;

  const schema = useMemo(() => createMasterAdminUserSchema(isEditMode), [isEditMode]);

  const form = useForm<MasterAdminUserFormData>({
    resolver: zodResolver(schema),
    defaultValues: {
      username: "",
      email: "",
      password: "",
      roleIds: [],
      enabled: true,
      mustChangePassword: false,
      passwordValidityDays: null,
      accountExpiryDate: "",
      credentialsExpiryDate: "",
      lockedUntil: "",
    },
  });

  useEffect(() => {
    if (!editData || !isEditMode) return;
    form.reset({
      username: editData.username,
      email: editData.email,
      password: "",
      roleIds: editData.roles.map((r) => r.roleId),
      enabled: editData.enabled,
      mustChangePassword: editData.mustChangePassword ?? false,
      passwordValidityDays: editData.passwordValidityDays ?? null,
      accountExpiryDate: isoToDateInput(editData.accountExpiryDate),
      credentialsExpiryDate: isoToDateInput(editData.credentialsExpiryDate),
      lockedUntil: isoToDateInput(editData.lockedUntil),
    });
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [editData, isEditMode]);

  const onSubmit = (data: MasterAdminUserFormData) => {
    if (isEditMode && editData) {
      const dto: MasterAdminUserUpdateRequestDTO = {
        email: data.email,
        roleIds: data.roleIds,
        enabled: data.enabled,
        mustChangePassword: data.mustChangePassword,
        passwordValidityDays: data.passwordValidityDays ?? null,
        accountExpiryDate: dateInputToIso(data.accountExpiryDate),
        credentialsExpiryDate: dateInputToIso(data.credentialsExpiryDate),
        lockedUntil: dateInputToIso(data.lockedUntil),
      };
      if (data.password && data.password.trim().length > 0) dto.password = data.password;
      updateUser({ dto, userId: editData.userId }, {
        onSuccess: () => { form.reset(); onSuccess?.(); },
      });
    } else {
      const dto: MasterAdminUserCreateRequestDTO = {
        username: data.username,
        email: data.email,
        password: data.password,
        roleIds: data.roleIds,
        enabled: data.enabled,
        mustChangePassword: data.mustChangePassword,
        passwordValidityDays: data.passwordValidityDays ?? null,
        accountExpiryDate: dateInputToIso(data.accountExpiryDate),
      };
      createUser(dto, {
        onSuccess: () => { form.reset(); onSuccess?.(); },
      });
    }
  };

  const watchedRoleIds = useWatch({ control: form.control, name: "roleIds" });

  const selectedRoleNames = useMemo(() => {
    if (!Array.isArray(roles) || !watchedRoleIds?.length) return [];
    return roles
      .filter((r) => watchedRoleIds.includes(r.roleId))
      .map((r) => r.roleName.replace("ROLE_", ""));
  }, [roles, watchedRoleIds]);

  // ── Shared input class ───────────────────────────────────────────────────────
  const inputClass = "h-9 bg-surface border-gs-line text-t1 placeholder:text-t4 focus-visible:ring-brand focus-visible:border-brand transition-colors";
  const labelClass = "text-xs font-semibold text-t2 uppercase tracking-wide";
  const descClass = "text-xs text-t4";

  // ── Loading / error ──────────────────────────────────────────────────────────
  if (isEditMode && userDataLoading) {
    return (
      <div className="flex items-center justify-center py-10">
        <div className="text-center space-y-2">
          <Loader2 className="w-7 h-7 animate-spin mx-auto text-brand" />
          <p className="text-sm text-t3">Loading user data…</p>
        </div>
      </div>
    );
  }

  if (isEditMode && userDataError) {
    return (
      <Alert className="border-destructive/30 bg-destructive/10">
        <AlertCircle className="h-4 w-4 text-destructive" />
        <AlertTitle className="text-destructive">Error loading user</AlertTitle>
        <AlertDescription className="text-destructive/80">
          Unable to fetch user data. Please try again.
        </AlertDescription>
      </Alert>
    );
  }

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-5">

        {/* Edit-mode hint */}
        {isEditMode && (
          <Alert className="border-brand-border bg-brand-soft py-2.5 px-3">
            <Info className="h-3.5 w-3.5 text-brand" />
            <AlertDescription className="text-xs text-brand/80 ml-1">
              Leave the password field empty to keep the current password unchanged.
            </AlertDescription>
          </Alert>
        )}

        {/* ── Section: Identity ─────────────────────────────────────────── */}
        <SectionBlock label="Identity">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <FormField control={form.control} name="username" render={({ field }) => (
              <FormItem className="space-y-1">
                <FormLabel className={labelClass}>Username *</FormLabel>
                <FormControl>
                  <Input placeholder="johndoe" {...field} disabled={isEditMode} className={inputClass} />
                </FormControl>
                {isEditMode && <FormDescription className={descClass}>Cannot be changed</FormDescription>}
                <FormMessage className="text-xs" />
              </FormItem>
            )} />

            <FormField control={form.control} name="email" render={({ field }) => (
              <FormItem className="space-y-1">
                <FormLabel className={labelClass}>Email *</FormLabel>
                <FormControl>
                  <Input type="email" placeholder="john@example.com" {...field} className={inputClass} />
                </FormControl>
                <FormMessage className="text-xs" />
              </FormItem>
            )} />

            <FormField control={form.control} name="password" render={({ field }) => (
              <FormItem className="space-y-1 md:col-span-2">
                <FormLabel className={labelClass}>
                  Password {isEditMode ? <span className="normal-case font-normal text-t4">(optional)</span> : "*"}
                </FormLabel>
                <FormControl>
                  <Input
                    type="password"
                    placeholder={isEditMode ? "Leave empty to keep current password" : "Enter a strong password"}
                    {...field}
                    className={inputClass}
                  />
                </FormControl>
                {!isEditMode && (
                  <FormDescription className={descClass}>
                    8+ characters with uppercase, lowercase, number and special character.
                  </FormDescription>
                )}
                <FormMessage className="text-xs" />
              </FormItem>
            )} />
          </div>
        </SectionBlock>

        {/* ── Section: Expiry & Lifecycle ───────────────────────────────── */}
        <SectionBlock label="Expiry & Lifecycle">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <FormField control={form.control} name="accountExpiryDate" render={({ field }) => (
              <FormItem className="space-y-1">
                <FormLabel className={labelClass}>Account Expiry</FormLabel>
                <FormControl>
                  <Input type="date" {...field} value={field.value ?? ""} className={inputClass} />
                </FormControl>
                <FormDescription className={descClass}>Leave blank for no expiry</FormDescription>
                <FormMessage className="text-xs" />
              </FormItem>
            )} />

            {isEditMode && (
              <FormField control={form.control} name="credentialsExpiryDate" render={({ field }) => (
                <FormItem className="space-y-1">
                  <FormLabel className={labelClass}>Credentials Expiry</FormLabel>
                  <FormControl>
                    <Input type="date" {...field} value={field.value ?? ""} className={inputClass} />
                  </FormControl>
                  <FormDescription className={descClass}>Leave blank for no expiry</FormDescription>
                  <FormMessage className="text-xs" />
                </FormItem>
              )} />
            )}

            {isEditMode && (
              <FormField control={form.control} name="lockedUntil" render={({ field }) => (
                <FormItem className="space-y-1">
                  <FormLabel className={labelClass}>Locked Until</FormLabel>
                  <FormControl>
                    <Input type="date" {...field} value={field.value ?? ""} className={inputClass} />
                  </FormControl>
                  <FormDescription className={descClass}>Manually lock account until this date</FormDescription>
                  <FormMessage className="text-xs" />
                </FormItem>
              )} />
            )}

            <FormField control={form.control} name="passwordValidityDays" render={({ field }) => (
              <FormItem className="space-y-1">
                <FormLabel className={labelClass}>Password Validity (days)</FormLabel>
                <FormControl>
                  <Input
                    type="number"
                    min={1}
                    placeholder="e.g. 90"
                    className={inputClass}
                    value={field.value ?? ""}
                    onChange={(e) =>
                      field.onChange(e.target.value === "" ? null : parseInt(e.target.value, 10))
                    }
                  />
                </FormControl>
                <FormDescription className={descClass}>Leave blank for no forced rotation</FormDescription>
                <FormMessage className="text-xs" />
              </FormItem>
            )} />
          </div>
        </SectionBlock>

        {/* ── Section: Account Flags ────────────────────────────────────── */}
        <SectionBlock label="Account Flags">
          <div className="flex flex-wrap gap-4">
            <FormField control={form.control} name="enabled" render={({ field }) => (
              <FormItem className="flex items-center gap-2.5 space-y-0 rounded-gs border border-gs-line bg-surface px-3 py-2.5">
                <FormControl>
                  <Switch
                    checked={field.value}
                    onCheckedChange={field.onChange}
                    className="data-[state=checked]:bg-brand"
                  />
                </FormControl>
                <FormLabel className="text-sm font-medium text-t1 cursor-pointer">Enabled</FormLabel>
              </FormItem>
            )} />

            <FormField control={form.control} name="mustChangePassword" render={({ field }) => (
              <FormItem className="flex items-center gap-2.5 space-y-0 rounded-gs border border-gs-line bg-surface px-3 py-2.5">
                <FormControl>
                  <Switch
                    checked={field.value}
                    onCheckedChange={field.onChange}
                    className="data-[state=checked]:bg-brand"
                  />
                </FormControl>
                <FormLabel className="text-sm font-medium text-t1 cursor-pointer">
                  Force password change on next login
                </FormLabel>
              </FormItem>
            )} />
          </div>
        </SectionBlock>

        {/* ── Section: Roles ────────────────────────────────────────────── */}
        <SectionBlock
          label="Roles"
          icon={<ShieldCheck className="w-3.5 h-3.5 text-brand" />}
          aside={
            selectedRoleNames.length > 0 ? (
              <div className="flex flex-wrap gap-1">
                {selectedRoleNames.map((name) => (
                  <Badge
                    key={name}
                    className="text-[10px] px-1.5 py-0 bg-brand-soft text-brand border-brand-border"
                  >
                    {name}
                  </Badge>
                ))}
              </div>
            ) : null
          }
        >
          {rolesLoading && (
            <div className="flex items-center gap-2 py-4 text-sm text-t3">
              <Loader2 className="w-4 h-4 animate-spin text-brand" />
              Loading roles…
            </div>
          )}

          {rolesError && (
            <Alert className="border-destructive/30 bg-destructive/10 py-2">
              <AlertCircle className="h-3.5 w-3.5 text-destructive" />
              <AlertDescription className="text-xs text-destructive/80 ml-1">
                Unable to fetch roles. Please try again.
              </AlertDescription>
            </Alert>
          )}

          {Array.isArray(roles) && roles.length > 0 && (
            <div className="space-y-1.5">
              {roles.map((role) => (
                <FormField key={role.roleId} control={form.control} name="roleIds" render={({ field }) => {
                  const checked = field.value?.includes(role.roleId);
                  return (
                    <FormItem
                      className={cn(
                        "flex flex-row items-start gap-3 space-y-0 rounded-gs border p-3 transition-colors cursor-pointer",
                        checked
                          ? "bg-brand-soft border-brand-border"
                          : "bg-surface border-gs-line hover:bg-surface-2"
                      )}
                    >
                      <FormControl>
                        <Checkbox
                          checked={checked}
                          onCheckedChange={(val) =>
                            field.onChange(
                              val
                                ? [...(field.value ?? []), role.roleId]
                                : (field.value ?? []).filter((id) => id !== role.roleId)
                            )
                          }
                          className="border-gs-line-2 data-[state=checked]:bg-brand data-[state=checked]:border-brand mt-0.5"
                        />
                      </FormControl>
                      <div className="flex-1 space-y-0.5 leading-none min-w-0">
                        <FormLabel className={cn("font-semibold cursor-pointer text-sm", checked ? "text-brand" : "text-t1")}>
                          {role.roleName.replace("ROLE_", "")}
                          {checked && <CheckCircle2 className="inline w-3.5 h-3.5 ml-1.5 text-brand" />}
                        </FormLabel>
                        {role.description && (
                          <p className={cn("text-xs", checked ? "text-brand/70" : "text-t3")}>
                            {role.description}
                          </p>
                        )}
                      </div>
                    </FormItem>
                  );
                }} />
              ))}
            </div>
          )}

          {Array.isArray(roles) && roles.length === 0 && !rolesLoading && (
            <div className="flex items-center gap-2 py-3 text-xs text-t4 border border-gs-line rounded-gs px-3 bg-surface-2">
              <Info className="h-3.5 w-3.5 shrink-0" />
              No roles available. Please contact an administrator.
            </div>
          )}

          <FormMessage className="text-xs" />
        </SectionBlock>

        {/* ── Submit ────────────────────────────────────────────────────── */}
        <div className="flex gap-2 pt-1">
          <Button
            type="submit"
            className="flex-1 bg-brand hover:bg-brand-hover text-white h-9"
            disabled={isPending || rolesLoading}
          >
            {isPending && <Loader2 className="mr-2 h-3.5 w-3.5 animate-spin" />}
            {isEditMode ? "Update User" : "Create User"}
          </Button>
        </div>
      </form>
    </Form>
  );
}

// ── Section wrapper ────────────────────────────────────────────────────────────
function SectionBlock({
  label,
  icon,
  aside,
  children,
}: {
  label: string;
  icon?: React.ReactNode;
  aside?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-gs border border-gs-line overflow-hidden">
      <div className="flex items-center justify-between px-3 py-2 bg-surface-2 border-b border-gs-line">
        <div className="flex items-center gap-1.5">
          {icon}
          <span className="text-[10px] font-bold uppercase tracking-widest text-t3">
            {label}
          </span>
        </div>
        {aside && <div>{aside}</div>}
      </div>
      <div className="p-3">{children}</div>
    </div>
  );
}