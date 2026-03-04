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
import { Loader2, Info, AlertCircle, ShieldCheck } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { useMemo, useEffect } from "react";
import { Badge } from "@/components/ui/badge";
import { useQueryGetRoles } from "../../role/role.react.query";

// ─── Helper: convert date string <input type="date"> → ISO datetime or null ──

function dateInputToIso(value?: string | null): string | null {
  if (!value) return null;
  // "2025-12-31" → "2025-12-31T00:00:00"
  return `${value}T00:00:00`;
}

function isoToDateInput(value?: string | null): string {
  if (!value) return "";
  // "2025-12-31T00:00:00" → "2025-12-31"
  return value.split("T")[0];
}

// ─── Props ────────────────────────────────────────────────────────────────────

interface CreateUserFormProps {
  onSuccess?: () => void;
  userId?: number;
}

// ─── Component ────────────────────────────────────────────────────────────────

export function CreateUserForm({ onSuccess, userId }: CreateUserFormProps) {
  const isEditMode = !!userId;

  const {
    data: editData,
    isLoading: userDataLoading,
    error: userDataError,
  } = useGetUserById(isEditMode ? userId : undefined);

  // Fetch roles
  const {
    roles,
    isLoading: rolesLoading,
    error: rolesError,
  } = useQueryGetRoles();

  const { mutate: createUser, isPending: isCreating } = useCreateUser();
  const { mutate: updateUser, isPending: isUpdating } = useUpdateUser();
  const isPending = isEditMode ? isUpdating : isCreating;

  // Create schema based on mode
  const schema = useMemo(
    () => createMasterAdminUserSchema(isEditMode),
    [isEditMode],
  );

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

  // Populate form when editing
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
  }, [editData, isEditMode, form]);

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
      // Only send password if the user typed one
      if (data.password && data.password.trim().length > 0) {
        dto.password = data.password;
      }

      updateUser(
        { dto, userId: editData.userId },
        {
          onSuccess: () => {
            form.reset();
            onSuccess?.();
          },
        },
      );
    } else {
      // CREATE MODE
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
        onSuccess: () => {
          form.reset();
          onSuccess?.();
        },
      });
    }
  };

  // ─── Derived UI state ────────────────────────────────────────────────────────
  
  const watchedRoleIds = useWatch({
    control: form.control,
    name: "roleIds",
  });

  // 3. Your memoized variable remains the same
  const selectedRoleNames = useMemo(() => {
    if (!Array.isArray(roles) || !watchedRoleIds?.length) return [];
    return roles
      .filter((r) => watchedRoleIds.includes(r.roleId))
      .map((r) => r.roleName.replace("ROLE_", ""));
  }, [roles, watchedRoleIds]);

  // ─── Loading / error states ──────────────────────────────────────────────────

  if (isEditMode && userDataLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="text-center space-y-3">
          <Loader2 className="w-8 h-8 animate-spin mx-auto text-primary" />
          <p className="text-sm text-muted-foreground">Loading user data…</p>
        </div>
      </div>
    );
  }

  if (isEditMode && userDataError) {
    return (
      <Alert variant="destructive">
        <AlertCircle className="h-4 w-4" />
        <AlertTitle>Error loading user</AlertTitle>
        <AlertDescription>
          Unable to fetch user data. Please try again.
        </AlertDescription>
      </Alert>
    );
  }

  // ─── Render ──────────────────────────────────────────────────────────────────

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
        {/* Edit-mode hint */}
        {isEditMode && (
          <Alert>
            <Info className="h-4 w-4" />
            <AlertDescription>
              Leave the password field empty to keep the current password
              unchanged. Only fill it in if you want to reset it.
            </AlertDescription>
          </Alert>
        )}

        {/* ── Core identity ─────────────────────────────────────────────── */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <FormField
            control={form.control}
            name="username"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Username *</FormLabel>
                <FormControl>
                  <Input
                    placeholder="johndoe"
                    {...field}
                    disabled={isEditMode}
                  />
                </FormControl>
                {isEditMode && (
                  <FormDescription className="text-xs">
                    Username cannot be changed
                  </FormDescription>
                )}
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="email"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Email *</FormLabel>
                <FormControl>
                  <Input
                    type="email"
                    placeholder="john@example.com"
                    {...field}
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="password"
            render={({ field }) => (
              <FormItem className="md:col-span-2">
                <FormLabel>
                  Password{" "}
                  {isEditMode
                    ? "(Optional — leave empty to keep current)"
                    : "*"}
                </FormLabel>
                <FormControl>
                  <Input
                    type="password"
                    placeholder={
                      isEditMode
                        ? "Leave empty to keep current password"
                        : "Enter a strong password"
                    }
                    {...field}
                  />
                </FormControl>
                {!isEditMode && (
                  <FormDescription>
                    Must be 8+ characters with uppercase, lowercase, number, and
                    special character. Common passwords are not allowed.
                  </FormDescription>
                )}
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        {/* ── Lifecycle / expiry dates ───────────────────────────────────── */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <FormField
            control={form.control}
            name="accountExpiryDate"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Account Expiry Date</FormLabel>
                <FormDescription className="text-xs">
                  Leave blank for no expiry
                </FormDescription>
                <FormControl>
                  <Input type="date" {...field} value={field.value ?? ""} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          {isEditMode && (
            <FormField
              control={form.control}
              name="credentialsExpiryDate"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Credentials Expiry Date</FormLabel>
                  <FormDescription className="text-xs">
                    Leave blank for no expiry
                  </FormDescription>
                  <FormControl>
                    <Input type="date" {...field} value={field.value ?? ""} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
          )}

          {isEditMode && (
            <FormField
              control={form.control}
              name="lockedUntil"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Locked Until</FormLabel>
                  <FormDescription className="text-xs">
                    Set a date to manually lock the account until then
                  </FormDescription>
                  <FormControl>
                    <Input type="date" {...field} value={field.value ?? ""} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
          )}

          <FormField
            control={form.control}
            name="passwordValidityDays"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Password Validity (days)</FormLabel>
                <FormDescription className="text-xs">
                  How many days until the password expires. Leave blank for no
                  forced rotation.
                </FormDescription>
                <FormControl>
                  <Input
                    type="number"
                    min={1}
                    placeholder="e.g. 90"
                    value={field.value ?? ""}
                    onChange={(e) =>
                      field.onChange(
                        e.target.value === ""
                          ? null
                          : parseInt(e.target.value, 10),
                      )
                    }
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        {/* ── Account flags ─────────────────────────────────────────────── */}
        <div className="space-y-3">
          <p className="text-sm font-medium">Account Flags</p>
          <div className="flex flex-wrap gap-6">
            <FormField
              control={form.control}
              name="enabled"
              render={({ field }) => (
                <FormItem className="flex items-center space-x-2 space-y-0">
                  <FormControl>
                    <Switch
                      checked={field.value}
                      onCheckedChange={field.onChange}
                    />
                  </FormControl>
                  <FormLabel className="mt-0!">Enabled</FormLabel>
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="mustChangePassword"
              render={({ field }) => (
                <FormItem className="flex items-center space-x-2 space-y-0">
                  <FormControl>
                    <Switch
                      checked={field.value}
                      onCheckedChange={field.onChange}
                    />
                  </FormControl>
                  <FormLabel className="mt-0!">
                    Force password change on next login
                  </FormLabel>
                </FormItem>
              )}
            />
          </div>
        </div>

        {/* ── Roles ─────────────────────────────────────────────────────── */}
        <FormField
          control={form.control}
          name="roleIds"
          render={() => (
            <FormItem>
              <div className="mb-3">
                <FormLabel className="text-base">
                  <ShieldCheck className="inline-block w-4 h-4 mr-1 mb-0.5" />
                  User Roles *
                </FormLabel>
                <FormDescription>
                  Select at least one role for the user.
                </FormDescription>
                {selectedRoleNames.length > 0 && (
                  <div className="flex flex-wrap gap-1 mt-2">
                    {selectedRoleNames.map((name) => (
                      <Badge key={name} variant="secondary">
                        {name}
                      </Badge>
                    ))}
                  </div>
                )}
              </div>

              {rolesLoading && (
                <div className="flex items-center py-6 text-sm text-muted-foreground">
                  <Loader2 className="w-4 h-4 animate-spin mr-2" />
                  Loading roles…
                </div>
              )}

              {rolesError && (
                <Alert variant="destructive">
                  <AlertCircle className="h-4 w-4" />
                  <AlertTitle>Error loading roles</AlertTitle>
                  <AlertDescription>
                    Unable to fetch roles. Please try again.
                  </AlertDescription>
                </Alert>
              )}

              {Array.isArray(roles) && roles.length > 0 && (
                <div className="space-y-2 border rounded-lg p-4 bg-muted/30">
                  {roles.map((role) => (
                    <FormField
                      key={role.roleId}
                      control={form.control}
                      name="roleIds"
                      render={({ field }) => {
                        const checked = field.value?.includes(role.roleId);
                        return (
                          <FormItem
                            className={`flex flex-row items-start space-x-3 space-y-0 rounded-md border p-3 transition-colors ${
                              checked
                                ? "bg-primary/5 border-primary"
                                : "bg-background hover:bg-muted/50"
                            }`}
                          >
                            <FormControl>
                              <Checkbox
                                checked={checked}
                                onCheckedChange={(val) =>
                                  field.onChange(
                                    val
                                      ? [...(field.value ?? []), role.roleId]
                                      : (field.value ?? []).filter(
                                          (id) => id !== role.roleId,
                                        ),
                                  )
                                }
                              />
                            </FormControl>
                            <div className="flex-1 space-y-0.5 leading-none">
                              <FormLabel className="font-semibold cursor-pointer">
                                {role.roleName.replace("ROLE_", "")}
                              </FormLabel>
                              {role.description && (
                                <p className="text-sm text-muted-foreground">
                                  {role.description}
                                </p>
                              )}
                            </div>
                          </FormItem>
                        );
                      }}
                    />
                  ))}
                </div>
              )}

              {Array.isArray(roles) && roles.length === 0 && !rolesLoading && (
                <Alert>
                  <Info className="h-4 w-4" />
                  <AlertDescription>
                    No roles available. Please contact an administrator.
                  </AlertDescription>
                </Alert>
              )}

              <FormMessage />
            </FormItem>
          )}
        />

        {/* ── Submit ────────────────────────────────────────────────────── */}
        <div className="flex gap-2 pt-2">
          <Button
            type="submit"
            className="flex-1"
            disabled={isPending || rolesLoading}
          >
            {isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            {isEditMode ? "Update User" : "Create User"}
          </Button>
        </div>
      </form>
    </Form>
  );
}
