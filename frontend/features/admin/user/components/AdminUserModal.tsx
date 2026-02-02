"use client";

import React from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Shield,
  User,
  Mail,
  Calendar,
  Key,
  Lock,
  CheckCircle,
  XCircle,
  Loader2,
  UserCog,
  Clock,
  AlertCircle,
} from "lucide-react";
import { useGetUserById } from "../user.react.query";
import { SignUpMethod } from "../user.types";
import { AppRole } from "@/types/auth.types";


interface UserModalProps {
  userId: number;
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
}

export default function AdminUserModal({
  userId,
  open = false,
  onOpenChange = () => {},
}: UserModalProps) {
  const {
    data: userData,
    isLoading,
    error,
  } = useGetUserById(open && userId ? userId : undefined);

  const formatDateTime = (dateString?: string) => {
    if (!dateString) return "";
    return new Date(dateString).toLocaleString("en-GB", {
      day: "2-digit",
      month: "2-digit",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  const isExpired = (expireDate?: string) => {
    if (!expireDate) return false;
    return new Date(expireDate) < new Date();
  };

  const getRoleDisplayName = (role: AppRole) => {
    switch (role) {
      case AppRole.EMPLOYEE:
        return "Master Admin";
      case AppRole.ADMIN:
        return "Admin";
      case AppRole.USER:
        return "User";
      default:
        return role;
    }
  };

  const getSignUpMethodDisplay = (method?: SignUpMethod | null) => {
    if (!method) return null;
    switch (method) {
      case SignUpMethod.ADMIN_CREATED:
        return "Admin Created";
      case SignUpMethod.Email:
        return "Email";
      default:
        return method;
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-4xl max-h-[90vh]">
        <DialogHeader>
          <div className="flex items-start gap-4">
            <UserCog className="h-6 w-6 text-primary mt-1 shrink-0" />
            <div className="grow">
              <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3">
                <div>
                  <DialogTitle className="text-2xl font-bold">
                    {isLoading ? "Loading..." : userData?.username || "User Details"}
                  </DialogTitle>
                  {userData && (
                    <>
                      <p className="text-sm text-muted-foreground mt-1">
                        User ID: #{userData.userId}
                      </p>
                      <p className="text-sm text-muted-foreground">
                        {userData.email}
                      </p>
                    </>
                  )}
                </div>
                {userData && (
                  <div className="flex flex-wrap gap-2">
                    <Badge
                      variant={userData.enabled ? "default" : "destructive"}
                    >
                      {userData.enabled ? (
                        <CheckCircle className="w-3 h-3 mr-1" />
                      ) : (
                        <XCircle className="w-3 h-3 mr-1" />
                      )}
                      {userData.enabled ? "Enabled" : "Disabled"}
                    </Badge>
                    {userData.isTwoFactorEnabled && (
                      <Badge variant="secondary">
                        <Shield className="w-3 h-3 mr-1" />
                        2FA
                      </Badge>
                    )}
                    {isExpired(userData.accountExpiryDate) && (
                      <Badge variant="destructive">
                        <AlertCircle className="w-3 h-3 mr-1" />
                        Expired
                      </Badge>
                    )}
                  </div>
                )}
              </div>

              {userData && (
                <div className="flex flex-wrap items-center gap-2 mt-3">
                  {userData.roles.map((role) => (
                    <Badge key={role.roleId} variant="outline">
                      <Shield className="w-3 h-3 mr-1" />
                      {getRoleDisplayName(role.roleName)}
                    </Badge>
                  ))}
                  {userData.signUpMethod && (
                    <Badge variant="outline">
                      {getSignUpMethodDisplay(userData.signUpMethod)}
                    </Badge>
                  )}
                </div>
              )}
            </div>
          </div>
        </DialogHeader>

        <ScrollArea className="max-h-[calc(90vh-180px)] pr-4">
          {isLoading ? (
            <div className="flex items-center justify-center p-8">
              <Loader2 className="h-8 w-8 animate-spin text-primary" />
              <span className="ml-3 text-lg">Loading user details...</span>
            </div>
          ) : error ? (
            <div className="flex flex-col items-center justify-center p-8 text-center">
              <XCircle className="h-12 w-12 text-destructive mb-3" />
              <p className="text-destructive text-lg mb-2">
                Error loading user details
              </p>
              <p className="text-sm text-muted-foreground">
                {error.message || "Please try again later"}
              </p>
            </div>
          ) : userData ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pb-4">
              <div className="space-y-6">
                <Section
                  title="Account Details"
                  icon={<User className="h-4 w-4" />}
                >
                  <Info label="Username" value={userData.username} />
                  <Info label="Email" value={userData.email} />
                  <Info
                    label="User ID"
                    value={`#${userData.userId}`}
                    className="font-mono"
                  />
                  {userData.signUpMethod && (
                    <Info
                      label="Sign Up Method"
                      value={getSignUpMethodDisplay(userData.signUpMethod)}
                    />
                  )}
                </Section>

                <Section
                  title="Security Status"
                  icon={<Lock className="h-4 w-4" />}
                >
                  <div className="space-y-3">
                    <StatusBadge
                      label="Account Status"
                      isActive={userData.enabled}
                      activeText="Enabled"
                      inactiveText="Disabled"
                    />
                    <StatusBadge
                      label="Account Expiry"
                      isActive={userData.accountNonExpired}
                      activeText="Valid"
                      inactiveText="Expired"
                    />
                    <StatusBadge
                      label="Account Lock Status"
                      isActive={userData.accountNonLocked}
                      activeText="Unlocked"
                      inactiveText="Locked"
                    />
                    <StatusBadge
                      label="Credentials Status"
                      isActive={userData.credentialsNonExpired}
                      activeText="Valid"
                      inactiveText="Expired"
                    />
                  </div>
                </Section>

                <Section
                  title="Two-Factor Authentication"
                  icon={<Shield className="h-4 w-4" />}
                >
                  <div
                    className={`p-4 rounded-lg border ${
                      userData.isTwoFactorEnabled
                        ? "bg-green-50 dark:bg-green-950 border-green-200 dark:border-green-800"
                        : "bg-muted"
                    }`}
                  >
                    <Info
                      label="2FA Status"
                      value={
                        userData.isTwoFactorEnabled ? "Enabled" : "Disabled"
                      }
                      className={
                        userData.isTwoFactorEnabled
                          ? "text-green-700 dark:text-green-400 font-medium"
                          : ""
                      }
                    />
                    {userData.twoFactorSecret && (
                      <Info
                        label="Secret Configured"
                        value="Yes"
                        className="text-green-700 dark:text-green-400 mt-2"
                      />
                    )}
                  </div>
                </Section>
              </div>

              <div className="space-y-6">
                <Section
                  title="Expiration Dates"
                  icon={<Calendar className="h-4 w-4" />}
                >
                  <div className="space-y-4">
                    <div
                      className={`p-4 rounded-lg border ${
                        isExpired(userData.accountExpiryDate)
                          ? "bg-red-50 dark:bg-red-950 border-red-200 dark:border-red-800"
                          : "bg-blue-50 dark:bg-blue-950 border-blue-200 dark:border-blue-800"
                      }`}
                    >
                      <Info
                        label="Account Expiry Date"
                        value={formatDateTime(userData.accountExpiryDate)}
                        className={
                          isExpired(userData.accountExpiryDate)
                            ? "text-red-700 dark:text-red-400 font-medium"
                            : "text-blue-700 dark:text-blue-400"
                        }
                      />
                    </div>

                    <div
                      className={`p-4 rounded-lg border ${
                        isExpired(userData.credentialsExpiryDate)
                          ? "bg-red-50 dark:bg-red-950 border-red-200 dark:border-red-800"
                          : "bg-blue-50 dark:bg-blue-950 border-blue-200 dark:border-blue-800"
                      }`}
                    >
                      <Info
                        label="Credentials Expiry Date"
                        value={formatDateTime(userData.credentialsExpiryDate)}
                        className={
                          isExpired(userData.credentialsExpiryDate)
                            ? "text-red-700 dark:text-red-400 font-medium"
                            : "text-blue-700 dark:text-blue-400"
                        }
                      />
                    </div>
                  </div>
                </Section>

                <Section
                  title="Roles & Permissions"
                  icon={<Key className="h-4 w-4" />}
                >
                  <div className="space-y-2">
                    {userData.roles.length > 0 ? (
                      userData.roles.map((role) => (
                        <div
                          key={role.roleId}
                          className="flex flex-col gap-1 p-3 rounded-lg bg-purple-50 dark:bg-purple-950 border border-purple-200 dark:border-purple-800"
                        >
                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2">
                              <Shield className="h-4 w-4 text-purple-600 dark:text-purple-400" />
                              <span className="font-medium text-purple-900 dark:text-purple-100">
                                {getRoleDisplayName(role.roleName)}
                              </span>
                            </div>
                            <span className="text-xs text-purple-600 dark:text-purple-400">
                              ID: {role.roleId}
                            </span>
                          </div>
                          {role.description && (
                            <p className="text-xs text-purple-700 dark:text-purple-300 ml-6">
                              {role.description}
                            </p>
                          )}
                        </div>
                      ))
                    ) : (
                      <p className="text-sm text-muted-foreground">
                        No roles assigned
                      </p>
                    )}
                  </div>
                </Section>

                <Section
                  title="System Information"
                  icon={<Clock className="h-4 w-4" />}
                >
                  <Info
                    label="Created Date"
                    value={formatDateTime(userData.createdDate)}
                  />
                  <Info
                    label="Last Updated"
                    value={formatDateTime(userData.updatedDate)}
                  />
                </Section>
              </div>
            </div>
          ) : null}
        </ScrollArea>
      </DialogContent>
    </Dialog>
  );
}

function Section({
  title,
  children,
  icon,
}: {
  title: string;
  children: React.ReactNode;
  icon?: React.ReactNode;
}) {
  return (
    <div>
      <div className="flex items-center gap-2 mb-3">
        {icon && <span className="text-muted-foreground">{icon}</span>}
        <h3 className="font-semibold text-base text-foreground border-b border-border pb-1 w-full">
          {title}
        </h3>
      </div>
      <div className="space-y-3 pl-1">{children}</div>
    </div>
  );
}

function Info({
  label,
  value,
  className = "",
}: {
  label: string;
  value: React.ReactNode;
  className?: string;
}) {
  return (
    <div className="flex flex-col">
      <p className="text-xs text-muted-foreground">{label}</p>
      <p className={`text-sm ${className}`}>
        {value || (
          <span className="text-muted-foreground/70">Not provided</span>
        )}
      </p>
    </div>
  );
}

function StatusBadge({
  label,
  isActive,
  activeText,
  inactiveText,
}: {
  label: string;
  isActive: boolean;
  activeText: string;
  inactiveText: string;
}) {
  return (
    <div className="flex items-center justify-between p-3 rounded-lg border bg-card">
      <span className="text-sm text-muted-foreground">{label}</span>
      <Badge variant={isActive ? "default" : "destructive"}>
        {isActive ? (
          <CheckCircle className="w-3 h-3 mr-1" />
        ) : (
          <XCircle className="w-3 h-3 mr-1" />
        )}
        {isActive ? activeText : inactiveText}
      </Badge>
    </div>
  );
}