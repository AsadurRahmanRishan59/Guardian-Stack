"use client";

import React from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
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
  AlertTriangle,
  History,
  LogIn,
  ShieldAlert,
  RefreshCw,
  LockKeyhole,
  CalendarClock,
  UserCheck,
  Activity,
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

  // Helper functions for null-safe checks
  const isTrue = (value?: boolean | null): boolean => value === true;
  const isFalse = (value?: boolean | null): boolean => value === false;
  const isNotTrue = (value?: boolean | null): boolean => value !== true;

  const formatDateTime = (dateString?: string | null) => {
    if (!dateString) return "—";
    return new Date(dateString).toLocaleString("en-GB", {
      day: "2-digit",
      month: "short",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  const formatRelativeTime = (dateString?: string | null) => {
    if (!dateString) return null;
    const date = new Date(dateString);
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const days = Math.floor(diff / (1000 * 60 * 60 * 24));
    const hours = Math.floor(diff / (1000 * 60 * 60));
    const minutes = Math.floor(diff / (1000 * 60));

    if (days > 0) return `${days} day${days > 1 ? "s" : ""} ago`;
    if (hours > 0) return `${hours} hour${hours > 1 ? "s" : ""} ago`;
    if (minutes > 0) return `${minutes} minute${minutes > 1 ? "s" : ""} ago`;
    return "Just now";
  };

  const isExpired = (expireDate?: string | null) => {
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
      case SignUpMethod.EMAIL:
        return "Email";
      default:
        return method;
    }
  };

  const getSecurityScore = () => {
    if (!userData) return 0;
    let score = 0;
    if (userData.enabled) score += 20;
    if (isNotTrue(userData.accountLocked)) score += 20;
    if (isNotTrue(userData.accountExpired)) score += 20;
    if (isNotTrue(userData.credentialsExpired)) score += 20;
    if ((userData.failedLoginAttempts ?? 0) === 0) score += 20;
    return score;
  };

  const getSecurityScoreColor = (score: number) => {
    if (score >= 80) return "text-green-600 dark:text-green-400";
    if (score >= 60) return "text-yellow-600 dark:text-yellow-400";
    return "text-red-600 dark:text-red-400";
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-5xl max-h-[95vh] p-0 gap-0 overflow-hidden">
        {/* Header Section - Fixed */}
        <DialogHeader className="px-6 pt-6 pb-4 space-y-0 bg-gradient-to-br from-slate-50 to-slate-100 dark:from-slate-900 dark:to-slate-950 border-b">
          <div className="flex items-start gap-4">
            <div className="shrink-0 w-14 h-14 rounded-xl bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center shadow-lg">
              <UserCog className="h-7 w-7 text-white" />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3">
                <div className="min-w-0">
                  <DialogTitle className="text-2xl font-bold tracking-tight">
                    {isLoading ? (
                      <span className="text-muted-foreground">Loading...</span>
                    ) : (
                      userData?.username || "User Details"
                    )}
                  </DialogTitle>
                  {userData && (
                    <div className="mt-1.5 space-y-0.5">
                      <p className="text-sm text-muted-foreground flex items-center gap-1.5">
                        <Mail className="h-3.5 w-3.5" />
                        {userData.email}
                      </p>
                      <p className="text-xs text-muted-foreground font-mono">
                        ID #{userData.userId}
                      </p>
                    </div>
                  )}
                </div>
                {userData && (
                  <div className="flex flex-wrap gap-2">
                    <Badge
                      variant={userData.enabled ? "default" : "destructive"}
                      className="shadow-sm"
                    >
                      {userData.enabled ? (
                        <CheckCircle className="w-3 h-3 mr-1" />
                      ) : (
                        <XCircle className="w-3 h-3 mr-1" />
                      )}
                      {userData.enabled ? "Active" : "Disabled"}
                    </Badge>
                    {isTrue(userData.accountLocked) && (
                      <Badge variant="destructive" className="shadow-sm">
                        <Lock className="w-3 h-3 mr-1" />
                        Locked
                      </Badge>
                    )}
                    {isTrue(userData.mustChangePassword) && (
                      <Badge variant="outline" className="shadow-sm border-yellow-300 text-yellow-700 dark:border-yellow-700 dark:text-yellow-400">
                        <AlertTriangle className="w-3 h-3 mr-1" />
                        Password Reset Required
                      </Badge>
                    )}
                  </div>
                )}
              </div>

              {userData && (
                <div className="flex flex-wrap items-center gap-2 mt-3">
                  {userData.roles.map((role) => (
                    <Badge
                      key={role.roleId}
                      variant="secondary"
                      className="shadow-sm"
                    >
                      <Shield className="w-3 h-3 mr-1" />
                      {getRoleDisplayName(role.roleName)}
                    </Badge>
                  ))}
                  {userData.signUpMethod && (
                    <Badge variant="outline" className="shadow-sm">
                      <UserCheck className="w-3 h-3 mr-1" />
                      {getSignUpMethodDisplay(userData.signUpMethod)}
                    </Badge>
                  )}
                </div>
              )}
            </div>
          </div>
        </DialogHeader>

        {/* Content Section - Scrollable */}
        <ScrollArea className="h-[calc(95vh-200px)]">
          {isLoading ? (
            <div className="flex items-center justify-center p-12">
              <div className="text-center space-y-3">
                <Loader2 className="h-10 w-10 animate-spin text-primary mx-auto" />
                <p className="text-muted-foreground">Loading user details...</p>
              </div>
            </div>
          ) : error ? (
            <div className="flex flex-col items-center justify-center p-12 text-center">
              <XCircle className="h-16 w-16 text-destructive mb-4" />
              <p className="text-destructive text-lg font-semibold mb-2">
                Error loading user details
              </p>
              <p className="text-sm text-muted-foreground">
                {error.message || "Please try again later"}
              </p>
            </div>
          ) : userData ? (
            <div className="p-6 space-y-6">
              {/* Security Overview Card */}
              <div className="bg-gradient-to-br from-blue-50 to-indigo-50 dark:from-blue-950/30 dark:to-indigo-950/30 rounded-xl p-5 border border-blue-200 dark:border-blue-800 shadow-sm">
                <div className="flex items-start justify-between mb-4">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-lg bg-blue-500 flex items-center justify-center">
                      <ShieldAlert className="h-5 w-5 text-white" />
                    </div>
                    <div>
                      <h3 className="font-semibold text-base">Security Overview</h3>
                      <p className="text-xs text-muted-foreground">Account security status</p>
                    </div>
                  </div>
                  <div className="text-right">
                    <div className={`text-3xl font-bold ${getSecurityScoreColor(getSecurityScore())}`}>
                      {getSecurityScore()}%
                    </div>
                    <p className="text-xs text-muted-foreground">Security Score</p>
                  </div>
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  <SecurityMetric
                    label="Account"
                    isSecure={userData.enabled && isNotTrue(userData.accountExpired)}
                    icon={<User className="w-4 h-4" />}
                  />
                  <SecurityMetric
                    label="Lock Status"
                    isSecure={isNotTrue(userData.accountLocked)}
                    icon={<Lock className="w-4 h-4" />}
                  />
                  <SecurityMetric
                    label="Credentials"
                    isSecure={isNotTrue(userData.credentialsExpired)}
                    icon={<Key className="w-4 h-4" />}
                  />
                  <SecurityMetric
                    label="Login Attempts"
                    isSecure={(userData.failedLoginAttempts ?? 0) === 0}
                    icon={<AlertCircle className="w-4 h-4" />}
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Left Column */}
                <div className="space-y-6">
                  {/* Account Status */}
                  <Card
                    title="Account Status"
                    icon={<Activity className="h-4 w-4" />}
                  >
                    <div className="space-y-3">
                      <StatusRow
                        label="Account Status"
                        isActive={userData.enabled}
                        activeText="Enabled"
                        inactiveText="Disabled"
                      />
                      <StatusRow
                        label="Account Lock"
                        isActive={isNotTrue(userData.accountLocked)}
                        activeText="Unlocked"
                        inactiveText="Locked"
                      />
                      <StatusRow
                        label="Account Expiry"
                        isActive={isNotTrue(userData.accountExpired)}
                        activeText="Valid"
                        inactiveText="Expired"
                      />
                      <StatusRow
                        label="Credentials"
                        isActive={isNotTrue(userData.credentialsExpired)}
                        activeText="Valid"
                        inactiveText="Expired"
                      />
                    </div>
                  </Card>

                  {/* Login Forensics */}
                  <Card
                    title="Login Forensics"
                    icon={<LogIn className="h-4 w-4" />}
                  >
                    <div className="space-y-4">
                      <InfoRow
                        icon={<AlertCircle className="h-4 w-4 text-red-500" />}
                        label="Failed Login Attempts"
                        value={
                          <span className={(userData.failedLoginAttempts ?? 0) > 0 ? "font-semibold text-red-600 dark:text-red-400" : ""}>
                            {userData.failedLoginAttempts ?? 0}
                          </span>
                        }
                      />
                      {userData.lastFailedLogin && (
                        <InfoRow
                          icon={<XCircle className="h-4 w-4 text-orange-500" />}
                          label="Last Failed Login"
                          value={
                            <div>
                              <div className="text-sm">{formatDateTime(userData.lastFailedLogin)}</div>
                              <div className="text-xs text-muted-foreground">
                                {formatRelativeTime(userData.lastFailedLogin)}
                              </div>
                            </div>
                          }
                        />
                      )}
                      {userData.lastSuccessfulLogin && (
                        <InfoRow
                          icon={<CheckCircle className="h-4 w-4 text-green-500" />}
                          label="Last Successful Login"
                          value={
                            <div>
                              <div className="text-sm">{formatDateTime(userData.lastSuccessfulLogin)}</div>
                              <div className="text-xs text-muted-foreground">
                                {formatRelativeTime(userData.lastSuccessfulLogin)}
                              </div>
                            </div>
                          }
                        />
                      )}
                      {userData.lockedUntil && (
                        <InfoRow
                          icon={<LockKeyhole className="h-4 w-4 text-red-500" />}
                          label="Locked Until"
                          value={
                            <div className="text-sm font-semibold text-red-600 dark:text-red-400">
                              {formatDateTime(userData.lockedUntil)}
                            </div>
                          }
                        />
                      )}
                    </div>
                  </Card>

                  {/* Password Management */}
                  <Card
                    title="Password Management"
                    icon={<RefreshCw className="h-4 w-4" />}
                  >
                    <div className="space-y-4">
                      {userData.lastPasswordChange && (
                        <InfoRow
                          icon={<History className="h-4 w-4 text-blue-500" />}
                          label="Last Password Change"
                          value={
                            <div>
                              <div className="text-sm">{formatDateTime(userData.lastPasswordChange)}</div>
                              <div className="text-xs text-muted-foreground">
                                {formatRelativeTime(userData.lastPasswordChange)}
                              </div>
                            </div>
                          }
                        />
                      )}
                      <InfoRow
                        icon={<AlertTriangle className="h-4 w-4 text-yellow-500" />}
                        label="Must Change Password"
                        value={
                          <Badge variant={isTrue(userData.mustChangePassword) ? "destructive" : "secondary"}>
                            {isTrue(userData.mustChangePassword) ? "Yes" : "No"}
                          </Badge>
                        }
                      />
                    </div>
                  </Card>
                </div>

                {/* Right Column */}
                <div className="space-y-6">
                  {/* Expiration Management */}
                  <Card
                    title="Expiration Management"
                    icon={<CalendarClock className="h-4 w-4" />}
                  >
                    <div className="space-y-3">
                      <ExpiryCard
                        label="Account Expiry"
                        date={userData.accountExpiryDate}
                        isExpired={isExpired(userData.accountExpiryDate)}
                      />
                      <ExpiryCard
                        label="Credentials Expiry"
                        date={userData.credentialsExpiryDate}
                        isExpired={isExpired(userData.credentialsExpiryDate)}
                      />
                    </div>
                  </Card>

                  {/* Roles & Permissions */}
                  <Card
                    title="Roles & Permissions"
                    icon={<Key className="h-4 w-4" />}
                  >
                    <div className="space-y-2">
                      {userData.roles.length > 0 ? (
                        userData.roles.map((role) => (
                          <div
                            key={role.roleId}
                            className="p-3 rounded-lg bg-gradient-to-r from-purple-50 to-pink-50 dark:from-purple-950/30 dark:to-pink-950/30 border border-purple-200 dark:border-purple-800"
                          >
                            <div className="flex items-center justify-between mb-1">
                              <div className="flex items-center gap-2">
                                <Shield className="h-4 w-4 text-purple-600 dark:text-purple-400" />
                                <span className="font-semibold text-purple-900 dark:text-purple-100">
                                  {getRoleDisplayName(role.roleName)}
                                </span>
                              </div>
                              <span className="text-xs px-2 py-0.5 rounded-full bg-purple-200 dark:bg-purple-800 text-purple-700 dark:text-purple-300">
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
                        <p className="text-sm text-muted-foreground text-center py-4">
                          No roles assigned
                        </p>
                      )}
                    </div>
                  </Card>

                  {/* System Audit Trail */}
                  <Card
                    title="System Audit Trail"
                    icon={<Clock className="h-4 w-4" />}
                  >
                    <div className="space-y-4">
                      <InfoRow
                        icon={<Calendar className="h-4 w-4 text-green-500" />}
                        label="Created"
                        value={
                          <div>
                            <div className="text-sm">{formatDateTime(userData.createdAt)}</div>
                            {userData.createdBy && (
                              <div className="text-xs text-muted-foreground">
                                by {userData.createdBy}
                              </div>
                            )}
                          </div>
                        }
                      />
                      <Separator />
                      <InfoRow
                        icon={<Calendar className="h-4 w-4 text-blue-500" />}
                        label="Last Updated"
                        value={
                          <div>
                            <div className="text-sm">{formatDateTime(userData.updatedAt)}</div>
                            {userData.updatedBy && (
                              <div className="text-xs text-muted-foreground">
                                by {userData.updatedBy}
                              </div>
                            )}
                          </div>
                        }
                      />
                    </div>
                  </Card>
                </div>
              </div>
            </div>
          ) : null}
        </ScrollArea>
      </DialogContent>
    </Dialog>
  );
}

// Utility Components
function Card({
  title,
  children,
  icon,
}: {
  title: string;
  children: React.ReactNode;
  icon?: React.ReactNode;
}) {
  return (
    <div className="rounded-xl border bg-card shadow-sm overflow-hidden">
      <div className="px-4 py-3 bg-muted/50 border-b flex items-center gap-2">
        {icon && <span className="text-muted-foreground">{icon}</span>}
        <h3 className="font-semibold text-sm">{title}</h3>
      </div>
      <div className="p-4">{children}</div>
    </div>
  );
}

function InfoRow({
  icon,
  label,
  value,
}: {
  icon: React.ReactNode;
  label: string;
  value: React.ReactNode;
}) {
  return (
    <div className="flex items-start gap-3">
      <div className="mt-0.5">{icon}</div>
      <div className="flex-1 min-w-0">
        <p className="text-xs text-muted-foreground mb-1">{label}</p>
        <div className="text-sm break-words">
          {value || <span className="text-muted-foreground/70">Not set</span>}
        </div>
      </div>
    </div>
  );
}

function StatusRow({
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
    <div className="flex items-center justify-between p-2.5 rounded-lg border bg-background/50">
      <span className="text-sm text-muted-foreground">{label}</span>
      <Badge variant={isActive ? "default" : "destructive"} className="shadow-sm">
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

function SecurityMetric({
  label,
  isSecure,
  icon,
}: {
  label: string;
  isSecure: boolean;
  icon: React.ReactNode;
}) {
  return (
    <div className={`p-3 rounded-lg border ${isSecure ? "bg-green-50 dark:bg-green-950/20 border-green-200 dark:border-green-800" : "bg-red-50 dark:bg-red-950/20 border-red-200 dark:border-red-800"}`}>
      <div className={`flex items-center gap-1.5 mb-1 ${isSecure ? "text-green-700 dark:text-green-400" : "text-red-700 dark:text-red-400"}`}>
        {icon}
      </div>
      <div className="text-xs font-medium text-muted-foreground">{label}</div>
      <div className={`text-xs font-semibold mt-0.5 ${isSecure ? "text-green-700 dark:text-green-400" : "text-red-700 dark:text-red-400"}`}>
        {isSecure ? "Secure" : "Issue"}
      </div>
    </div>
  );
}

function ExpiryCard({
  label,
  date,
  isExpired,
}: {
  label: string;
  date?: string | null;
  isExpired: boolean;
}) {
  const formatDateTime = (dateString?: string | null) => {
    if (!dateString) return "Not set";
    return new Date(dateString).toLocaleString("en-GB", {
      day: "2-digit",
      month: "short",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  const getDaysUntilExpiry = (dateString?: string | null) => {
    if (!dateString) return null;
    const date = new Date(dateString);
    const now = new Date();
    const diff = date.getTime() - now.getTime();
    const days = Math.ceil(diff / (1000 * 60 * 60 * 24));
    return days;
  };

  const days = getDaysUntilExpiry(date);
  const hasDate = !!date;

  return (
    <div
      className={`p-3 rounded-lg border ${
        !hasDate
          ? "bg-muted/50 border-muted"
          : isExpired
          ? "bg-red-50 dark:bg-red-950/20 border-red-200 dark:border-red-800"
          : "bg-blue-50 dark:bg-blue-950/20 border-blue-200 dark:border-blue-800"
      }`}
    >
      <div className="flex items-start justify-between mb-1">
        <span className="text-xs font-medium text-muted-foreground">{label}</span>
        {hasDate && (
          <>
            {isExpired ? (
              <Badge variant="destructive" className="text-xs px-2 py-0">
                Expired
              </Badge>
            ) : days !== null && days < 30 ? (
              <Badge variant="outline" className="text-xs px-2 py-0 border-yellow-300 text-yellow-700 dark:border-yellow-700 dark:text-yellow-400">
                {days} days left
              </Badge>
            ) : null}
          </>
        )}
      </div>
      <div
        className={`text-sm font-semibold ${
          !hasDate
            ? "text-muted-foreground"
            : isExpired
            ? "text-red-700 dark:text-red-400"
            : "text-blue-700 dark:text-blue-400"
        }`}
      >
        {formatDateTime(date)}
      </div>
    </div>
  );
}