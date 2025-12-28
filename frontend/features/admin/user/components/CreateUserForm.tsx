// features/admin/user/CreateUserForm.tsx
"use client";

import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { createAdminUserSchema, AdminUserFormData } from "../user.schema";
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
  AdminUserUpdateRequestDTO,
  AdminUserCreateRequestDTO,
  SignUpMethod,
} from "../user.types";
import {
  useCreateUser,
  useGetUserById,
  useUpdateUser,
} from "../user.react.query";
import { Loader2, Info, AlertCircle } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { useMemo, useEffect } from "react";
import { Badge } from "@/components/ui/badge";
import { useQueryGetRoles } from "../../role/role.react.query";

interface CreateUserFormProps {
  onSuccess?: () => void;
  userId?: number;
}

export function CreateUserForm({ onSuccess, userId }: CreateUserFormProps) {
  const isEditMode = !!userId;

  const {
    data: editData,
    isLoading: userDataLoading,
    error: userDataError,
  } = useGetUserById(isEditMode && userId  ? userId : undefined);

  // Fetch roles
  const {
    roles,
    isLoading: rolesLoading,
    error: rolesError,
  } = useQueryGetRoles();

  // Use appropriate mutation hook based on mode
  const createUserMutation = useCreateUser();
  const updateUserMutation = useUpdateUser();

  const { mutate: createUser, isPending: isCreating } = createUserMutation;
  const { mutate: updateUser, isPending: isUpdating } = updateUserMutation;

  const isPending = isEditMode ? isUpdating : isCreating;

  // Create schema based on mode
  const schema = useMemo(() => createAdminUserSchema(isEditMode), [isEditMode]);

  const form = useForm<AdminUserFormData>({
    resolver: zodResolver(schema),
    defaultValues: {
      username: "",
      email: "",
      password: "",
      enabled: true,
      accountNonExpired: true,
      accountNonLocked: true,
      credentialsNonExpired: true,
      isTwoFactorEnabled: false,
      signUpMethod: SignUpMethod.ADMIN_CREATED,
      roleIds: [],
      credentialsExpiryDate: "",
      accountExpiryDate: "",
      twoFactorSecret: "",
    },
  });

  // Update form values when editData is loaded
  useEffect(() => {
    if (editData && isEditMode) {
      form.reset({
        username: editData.username,
        email: editData.email,
        password: "",
        enabled: editData.enabled,
        accountNonExpired: true,
        accountNonLocked: true,
        credentialsNonExpired: true,
        isTwoFactorEnabled: editData.isTwoFactorEnabled,
        signUpMethod: editData.signUpMethod || SignUpMethod.ADMIN_CREATED,
        roleIds: editData.roles.map((r) => r.roleId),
        credentialsExpiryDate: "",
        accountExpiryDate: "",
        twoFactorSecret: "",
      });
    }
  }, [editData, isEditMode, form]);

  const onSubmit = (data: AdminUserFormData) => {
    if (isEditMode && editData) {
      // UPDATE MODE
      const payload: Partial<AdminUserUpdateRequestDTO> = {
        email: data.email,
        enabled: data.enabled,
        accountNonExpired: data.accountNonExpired,
        accountNonLocked: data.accountNonLocked,
        credentialsNonExpired: data.credentialsNonExpired,
        credentialsExpiryDate: data.credentialsExpiryDate || "",
        accountExpiryDate: data.accountExpiryDate || "",
        twoFactorSecret: data.twoFactorSecret || "",
        isTwoFactorEnabled: data.isTwoFactorEnabled,
        signUpMethod: data.signUpMethod || SignUpMethod.ADMIN_CREATED,
        roleIds: data.roleIds,
      };

      // Only include password if it's provided and not empty
      if (data.password && data.password.trim().length > 0) {
        payload.password = data.password;
      }

      updateUser(
        { user: payload as AdminUserUpdateRequestDTO, userId: editData.userId },
        {
          onSuccess: () => {
            form.reset();
            onSuccess?.();
          },
        }
      );
    } else {
      // CREATE MODE
      const payload: AdminUserCreateRequestDTO = {
        username: data.username,
        email: data.email,
        password: data.password,
        enabled: data.enabled,
        accountNonExpired: data.accountNonExpired,
        accountNonLocked: data.accountNonLocked,
        credentialsNonExpired: data.credentialsNonExpired,
        credentialsExpiryDate: data.credentialsExpiryDate || "",
        accountExpiryDate: data.accountExpiryDate || "",
        twoFactorSecret: data.twoFactorSecret || "",
        isTwoFactorEnabled: data.isTwoFactorEnabled,
        signUpMethod: data.signUpMethod || SignUpMethod.ADMIN_CREATED,
        roleIds: data.roleIds,
      };

      createUser(payload, {
        onSuccess: () => {
          form.reset();
          onSuccess?.();
        },
      });
    }
  };

  const selectedRolesInfo = useMemo(() => {
    if (!roles || !Array.isArray(roles)) return null;

    const roleIds = form.getValues("roleIds") || [];
    if (roleIds.length === 0) return null;

    const selectedRoles = roles.filter((role) => roleIds.includes(role.roleId));

    return {
      count: selectedRoles.length,
      names: selectedRoles.map((r) => r.roleName.replace("ROLE_", "")),
    };
  }, [roles, form]); 

  // Show loading state while fetching user data in edit mode
  if (isEditMode && userDataLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="text-center space-y-3">
          <Loader2 className="w-8 h-8 animate-spin mx-auto text-primary" />
          <p className="text-sm text-muted-foreground">Loading user data...</p>
        </div>
      </div>
    );
  }

  // Show error if user data fails to load in edit mode
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

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
        {isEditMode && (
          <Alert>
            <Info className="h-4 w-4" />
            <AlertDescription>
              Leave the password field empty to keep the current password
              unchanged. Only fill it if you want to reset the user&apos;s
              password.
            </AlertDescription>
          </Alert>
        )}

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
                    disabled={isEditMode} // Username cannot be changed in edit mode
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
                    ? "(Optional - leave empty to keep current)"
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
                <FormDescription>
                  {isEditMode ? (
                    "Only fill this field if you want to change the user's password"
                  ) : (
                    <>
                      Must be 8+ characters with uppercase, lowercase, number,
                      and special character.
                      <br />
                      <span className="text-xs text-muted-foreground">
                        Common passwords like &quot;password&quot;,
                        &quot;12345678&quot; are not allowed.
                      </span>
                    </>
                  )}
                </FormDescription>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="signUpMethod"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Sign Up Method</FormLabel>
                <FormControl>
                  <Input placeholder="ADMIN_CREATED" {...field} disabled />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="twoFactorSecret"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Two-Factor Secret</FormLabel>
                <FormControl>
                  <Input placeholder="Optional" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="credentialsExpiryDate"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Credentials Expiry Date</FormLabel>
                <FormControl>
                  <Input type="date" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="accountExpiryDate"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Account Expiry Date</FormLabel>
                <FormControl>
                  <Input type="date" {...field} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        <div className="space-y-4">
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
              name="accountNonExpired"
              render={({ field }) => (
                <FormItem className="flex items-center space-x-2 space-y-0">
                  <FormControl>
                    <Switch
                      checked={field.value}
                      onCheckedChange={field.onChange}
                    />
                  </FormControl>
                  <FormLabel className="mt-0!">Account Non-Expired</FormLabel>
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="accountNonLocked"
              render={({ field }) => (
                <FormItem className="flex items-center space-x-2 space-y-0">
                  <FormControl>
                    <Switch
                      checked={field.value}
                      onCheckedChange={field.onChange}
                    />
                  </FormControl>
                  <FormLabel className="mt-0!">Account Non-Locked</FormLabel>
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="credentialsNonExpired"
              render={({ field }) => (
                <FormItem className="flex items-center space-x-2 space-y-0">
                  <FormControl>
                    <Switch
                      checked={field.value}
                      onCheckedChange={field.onChange}
                    />
                  </FormControl>
                  <FormLabel className="mt-0!">
                    Credentials Non-Expired
                  </FormLabel>
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="isTwoFactorEnabled"
              render={({ field }) => (
                <FormItem className="flex items-center space-x-2 space-y-0">
                  <FormControl>
                    <Switch
                      checked={field.value}
                      onCheckedChange={field.onChange}
                    />
                  </FormControl>
                  <FormLabel className="mt-0!">Two-Factor Enabled</FormLabel>
                </FormItem>
              )}
            />
          </div>

          {/* Roles Section */}
          <FormField
            control={form.control}
            name="roleIds"
            render={() => (
              <FormItem>
                <div className="mb-4">
                  <FormLabel className="text-base">User Roles *</FormLabel>
                  <FormDescription>
                    Select at least one role for the user
                    {selectedRolesInfo && (
                      <span className="block mt-1">
                        <Badge variant="secondary" className="mt-1">
                          {selectedRolesInfo.count} role
                          {selectedRolesInfo.count !== 1 ? "s" : ""} selected
                        </Badge>
                      </span>
                    )}
                  </FormDescription>
                </div>

                {rolesLoading && (
                  <div className="flex items-center justify-center py-8 text-sm text-muted-foreground">
                    <Loader2 className="w-4 h-4 animate-spin mr-2" />
                    Loading roles...
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

                {roles && Array.isArray(roles) && roles.length > 0 && (
                  <div className="space-y-3 border rounded-lg p-4 bg-muted/30">
                    {roles.map((role) => (
                      <FormField
                        key={role.roleId}
                        control={form.control}
                        name="roleIds"
                        render={({ field }) => {
                          const isChecked = field.value?.includes(role.roleId);
                          return (
                            <FormItem
                              key={role.roleId}
                              className={`flex flex-row items-start space-x-3 space-y-0 rounded-md border p-4 transition-colors ${
                                isChecked
                                  ? "bg-primary/5 border-primary"
                                  : "bg-background hover:bg-muted/50"
                              }`}
                            >
                              <FormControl>
                                <Checkbox
                                  checked={isChecked}
                                  onCheckedChange={(checked) => {
                                    return checked
                                      ? field.onChange([
                                          ...field.value,
                                          role.roleId,
                                        ])
                                      : field.onChange(
                                          field.value?.filter(
                                            (value) => value !== role.roleId
                                          )
                                        );
                                  }}
                                />
                              </FormControl>
                              <div className="flex-1 space-y-1 leading-none">
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

                {roles && Array.isArray(roles) && roles.length === 0 && (
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
        </div>

        <div className="flex gap-2 pt-4">
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
