// features/admin/user/MasterAdminUserModal.tsx
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
import { cn } from "@/lib/utils";

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
  // Latch: once opened, keep query enabled so React Query serves from cache.
  // useState is safe to read during render; we update it in a useEffect.
  const [queryEnabled, setQueryEnabled] = React.useState(false);

  React.useEffect(() => {
    if (open && userId) setQueryEnabled(true);
  }, [open, userId]);

  const { data: userData, isLoading, error } = useGetUserById(
    queryEnabled && userId ? userId : undefined
  );

  const isTrue = (v?: boolean | null) => v === true;
  const isNotTrue = (v?: boolean | null) => v !== true;

  const getRoleLabel = (role: AppRole) => {
    const map: Record<string, string> = {
      [AppRole.MASTER_ADMIN]: "Master Admin",
      [AppRole.ADMIN]: "Admin",
      [AppRole.EMPLOYEE]: "Employee",
      [AppRole.USER]: "User",
    };
    return map[role] ?? role;
  };

  const getSignUpLabel = (m?: SignUpMethod | null) => {
    if (!m) return null;
    return m === SignUpMethod.ADMIN_CREATED ? "Admin Created"
      : m === SignUpMethod.EMAIL ? "Email" : m;
  };

  const securityScore = () => {
    if (!userData) return 0;
    let s = 0;
    if (userData.enabled) s += 20;
    if (isNotTrue(userData.accountLocked)) s += 20;
    if (isNotTrue(userData.accountExpired)) s += 20;
    if (isNotTrue(userData.credentialsExpired)) s += 20;
    if ((userData.failedLoginAttempts ?? 0) === 0) s += 20;
    return s;
  };

  const scoreColor = (s: number) =>
    s >= 80 ? "text-gs-green" : s >= 60 ? "text-brand" : "text-destructive";

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-5xl max-h-[95vh] p-0 gap-0 overflow-hidden border-gs-line bg-surface-card">

        {/* ── Fixed header ── */}
        <DialogHeader className="px-4 pt-4 pb-3 border-b border-gs-line bg-surface-2/60">
          <div className="flex items-start gap-3">
            {/* Avatar */}
            <div className="shrink-0 w-11 h-11 rounded-gs bg-brand flex items-center justify-center shadow-sm">
              <UserCog className="h-5 w-5 text-white" />
            </div>

            <div className="flex-1 min-w-0">
              <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-2">
                <div className="min-w-0">
                  <DialogTitle className="text-base font-bold font-head text-t1 leading-tight">
                    {isLoading ? (
                      <span className="text-t4">Loading…</span>
                    ) : (
                      userData?.username ?? "User Details"
                    )}
                  </DialogTitle>
                  {userData && (
                    <div className="mt-0.5 space-y-0.5">
                      <p className="text-xs text-t3 flex items-center gap-1">
                        <Mail className="h-3 w-3" />
                        {userData.email}
                      </p>
                      <p className="text-[10px] text-t4 font-mono">ID #{userData.userId}</p>
                    </div>
                  )}
                </div>

                {userData && (
                  <div className="flex flex-wrap gap-1.5 shrink-0">
                    <StatusBadge active={userData.enabled} trueText="Active" falseText="Disabled" />
                    {isTrue(userData.accountLocked) && (
                      <Badge className="text-[10px] bg-destructive/10 text-destructive border-destructive/30 gap-1">
                        <Lock className="w-2.5 h-2.5" /> Locked
                      </Badge>
                    )}
                    {isTrue(userData.mustChangePassword) && (
                      <Badge className="text-[10px] bg-brand-soft text-brand border-brand-border gap-1">
                        <AlertTriangle className="w-2.5 h-2.5" /> Password Reset Required
                      </Badge>
                    )}
                  </div>
                )}
              </div>

              {userData && (
                <div className="flex flex-wrap gap-1.5 mt-2">
                  {userData.roles.map((role) => (
                    <Badge key={role.roleId} className="text-[10px] bg-surface-3 text-t2 border-gs-line gap-1">
                      <Shield className="w-2.5 h-2.5" />
                      {getRoleLabel(role.roleName)}
                    </Badge>
                  ))}
                  {userData.signUpMethod && (
                    <Badge className="text-[10px] bg-surface-3 text-t3 border-gs-line gap-1">
                      <UserCheck className="w-2.5 h-2.5" />
                      {getSignUpLabel(userData.signUpMethod)}
                    </Badge>
                  )}
                </div>
              )}
            </div>
          </div>
        </DialogHeader>

        {/* ── Scrollable body ── */}
        <ScrollArea className="h-[calc(95vh-130px)]">
          {isLoading ? (
            <div className="flex items-center justify-center p-12">
              <div className="text-center space-y-2">
                <Loader2 className="h-8 w-8 animate-spin text-brand mx-auto" />
                <p className="text-sm text-t3">Loading user details…</p>
              </div>
            </div>
          ) : error ? (
            <div className="flex flex-col items-center justify-center p-12 text-center gap-3">
              <XCircle className="h-12 w-12 text-destructive" />
              <p className="text-destructive font-semibold text-sm">Error loading user details</p>
              <p className="text-xs text-t4">{error.message || "Please try again later"}</p>
            </div>
          ) : userData ? (
            <div className="p-4 space-y-4">

              {/* ── Security overview ── */}
              <div className="rounded-gs border border-gs-line bg-surface-2/50 p-4">
                <div className="flex items-start justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <div className="w-8 h-8 rounded-gs bg-brand/10 flex items-center justify-center">
                      <ShieldAlert className="h-4 w-4 text-brand" />
                    </div>
                    <div>
                      <p className="text-xs font-bold uppercase tracking-widest text-t3">Security Overview</p>
                      <p className="text-[10px] text-t4">Account security status</p>
                    </div>
                  </div>
                  <div className="text-right">
                    <div className={cn("text-2xl font-bold font-head", scoreColor(securityScore()))}>
                      {securityScore()}%
                    </div>
                    <p className="text-[10px] text-t4">Security Score</p>
                  </div>
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                  <SecurityMetric label="Account" isSecure={userData.enabled && isNotTrue(userData.accountExpired)} icon={<User className="w-3.5 h-3.5" />} />
                  <SecurityMetric label="Lock Status" isSecure={isNotTrue(userData.accountLocked)} icon={<Lock className="w-3.5 h-3.5" />} />
                  <SecurityMetric label="Credentials" isSecure={isNotTrue(userData.credentialsExpired)} icon={<Key className="w-3.5 h-3.5" />} />
                  <SecurityMetric label="Login Attempts" isSecure={(userData.failedLoginAttempts ?? 0) === 0} icon={<AlertCircle className="w-3.5 h-3.5" />} />
                </div>
              </div>

              {/* ── Two-column grid ── */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">

                {/* Left column */}
                <div className="space-y-4">
                  <InfoCard title="Account Status" icon={<Activity className="h-3.5 w-3.5" />}>
                    <div className="space-y-1.5">
                      <StatusRow label="Account Status" isActive={userData.enabled} activeText="Enabled" inactiveText="Disabled" />
                      <StatusRow label="Account Lock" isActive={isNotTrue(userData.accountLocked)} activeText="Unlocked" inactiveText="Locked" />
                      <StatusRow label="Account Expiry" isActive={isNotTrue(userData.accountExpired)} activeText="Valid" inactiveText="Expired" />
                      <StatusRow label="Credentials" isActive={isNotTrue(userData.credentialsExpired)} activeText="Valid" inactiveText="Expired" />
                    </div>
                  </InfoCard>

                  <InfoCard title="Login Forensics" icon={<LogIn className="h-3.5 w-3.5" />}>
                    <div className="space-y-3">
                      <InfoRow
                        icon={<AlertCircle className="h-3.5 w-3.5 text-destructive" />}
                        label="Failed Login Attempts"
                        value={
                          <span className={cn("font-semibold", (userData.failedLoginAttempts ?? 0) > 0 ? "text-destructive" : "text-t1")}>
                            {userData.failedLoginAttempts ?? 0}
                          </span>
                        }
                      />
                      {userData.lastFailedLogin && (
                        <InfoRow
                          icon={<XCircle className="h-3.5 w-3.5 text-brand" />}
                          label="Last Failed Login"
                          value={<TimeValue date={userData.lastFailedLogin} />}
                        />
                      )}
                      {userData.lastSuccessfulLogin && (
                        <InfoRow
                          icon={<CheckCircle className="h-3.5 w-3.5 text-gs-green" />}
                          label="Last Successful Login"
                          value={<TimeValue date={userData.lastSuccessfulLogin} />}
                        />
                      )}
                      {userData.lockedUntil && (
                        <InfoRow
                          icon={<LockKeyhole className="h-3.5 w-3.5 text-destructive" />}
                          label="Locked Until"
                          value={<span className="text-sm font-semibold text-destructive">{formatDateTime(userData.lockedUntil)}</span>}
                        />
                      )}
                    </div>
                  </InfoCard>

                  <InfoCard title="Password Management" icon={<RefreshCw className="h-3.5 w-3.5" />}>
                    <div className="space-y-3">
                      {userData.lastPasswordChange && (
                        <InfoRow
                          icon={<History className="h-3.5 w-3.5 text-t3" />}
                          label="Last Password Change"
                          value={<TimeValue date={userData.lastPasswordChange} />}
                        />
                      )}
                      <InfoRow
                        icon={<AlertTriangle className="h-3.5 w-3.5 text-brand" />}
                        label="Must Change Password"
                        value={
                          <Badge className={cn("text-[10px]", isTrue(userData.mustChangePassword)
                            ? "bg-brand-soft text-brand border-brand-border"
                            : "bg-gs-green-bg text-gs-green border-transparent")}>
                            {isTrue(userData.mustChangePassword) ? "Yes" : "No"}
                          </Badge>
                        }
                      />
                    </div>
                  </InfoCard>
                </div>

                {/* Right column */}
                <div className="space-y-4">
                  <InfoCard title="Expiration Management" icon={<CalendarClock className="h-3.5 w-3.5" />}>
                    <div className="space-y-2">
                      <ExpiryCard label="Account Expiry" date={userData.accountExpiryDate} />
                      <ExpiryCard label="Credentials Expiry" date={userData.credentialsExpiryDate} />
                    </div>
                  </InfoCard>

                  <InfoCard title="Roles & Permissions" icon={<Key className="h-3.5 w-3.5" />}>
                    <div className="space-y-1.5">
                      {userData.roles.length > 0 ? userData.roles.map((role) => (
                        <div key={role.roleId} className="flex items-center justify-between rounded-gs border border-gs-line bg-surface-2/50 px-3 py-2.5">
                          <div className="flex items-center gap-2 min-w-0">
                            <Shield className="h-3.5 w-3.5 text-brand shrink-0" />
                            <div className="min-w-0">
                              <p className="text-sm font-semibold text-t1 truncate">{getRoleLabel(role.roleName)}</p>
                              {role.description && <p className="text-xs text-t3 truncate">{role.description}</p>}
                            </div>
                          </div>
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-surface-3 text-t4 font-mono shrink-0 ml-2">
                            #{role.roleId}
                          </span>
                        </div>
                      )) : (
                        <p className="text-xs text-t4 text-center py-3">No roles assigned</p>
                      )}
                    </div>
                  </InfoCard>

                  <InfoCard title="System Audit Trail" icon={<Clock className="h-3.5 w-3.5" />}>
                    <div className="space-y-3">
                      <InfoRow
                        icon={<Calendar className="h-3.5 w-3.5 text-gs-green" />}
                        label="Created"
                        value={
                          <div>
                            <p className="text-sm text-t1">{formatDateTime(userData.createdAt)}</p>
                            {userData.createdBy && <p className="text-[10px] text-t4">by {userData.createdBy}</p>}
                          </div>
                        }
                      />
                      <Separator className="bg-gs-line" />
                      <InfoRow
                        icon={<Calendar className="h-3.5 w-3.5 text-t3" />}
                        label="Last Updated"
                        value={
                          <div>
                            <p className="text-sm text-t1">{formatDateTime(userData.updatedAt)}</p>
                            {userData.updatedBy && <p className="text-[10px] text-t4">by {userData.updatedBy}</p>}
                          </div>
                        }
                      />
                    </div>
                  </InfoCard>
                </div>
              </div>
            </div>
          ) : null}
        </ScrollArea>
      </DialogContent>
    </Dialog>
  );
}

// ── Pure helpers (defined outside any component so they never cause impure-render errors) ──

function formatDateTime(d?: string | null): string {
  if (!d) return "—";
  return new Date(d).toLocaleString("en-GB", {
    day: "2-digit", month: "short", year: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}

function formatRelative(d?: string | null): string | null {
  if (!d) return null;
  // snapshot `now` once per call — fine here because this is not called during React's render phase
  const now = new Date();
  const diff = now.getTime() - new Date(d).getTime();
  const mins = Math.floor(diff / 60000);
  const hrs  = Math.floor(diff / 3600000);
  const days = Math.floor(diff / 86400000);
  if (days > 0) return `${days}d ago`;
  if (hrs  > 0) return `${hrs}h ago`;
  if (mins > 0) return `${mins}m ago`;
  return "Just now";
}

function isExpired(d?: string | null): boolean {
  if (!d) return false;
  return new Date(d) < new Date();
}

function getDaysLeft(d?: string | null): number | null {
  if (!d) return null;
  return Math.ceil((new Date(d).getTime() - new Date().getTime()) / 86400000);
}

// ── Utility components ────────────────────────────────────────────────────────

function InfoCard({ title, icon, children }: { title: string; icon?: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="rounded-gs border border-gs-line overflow-hidden">
      <div className="flex items-center gap-1.5 px-3 py-2 bg-surface-2 border-b border-gs-line">
        {icon && <span className="text-t3">{icon}</span>}
        <h3 className="text-[10px] font-bold uppercase tracking-widest text-t3">{title}</h3>
      </div>
      <div className="p-3">{children}</div>
    </div>
  );
}

function InfoRow({ icon, label, value }: { icon: React.ReactNode; label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-start gap-2.5">
      <div className="mt-0.5 shrink-0">{icon}</div>
      <div className="flex-1 min-w-0">
        <p className="text-[10px] text-t4 mb-0.5 uppercase tracking-wide">{label}</p>
        <div className="text-sm text-t1 break-words">
          {value ?? <span className="text-t4">Not set</span>}
        </div>
      </div>
    </div>
  );
}

function TimeValue({ date }: { date: string }) {
  return (
    <div>
      <p className="text-sm text-t1">{formatDateTime(date)}</p>
      <p className="text-[10px] text-t4">{formatRelative(date)}</p>
    </div>
  );
}

function StatusRow({ label, isActive, activeText, inactiveText }: {
  label: string; isActive: boolean; activeText: string; inactiveText: string;
}) {
  return (
    <div className="flex items-center justify-between px-2.5 py-2 rounded-gs border border-gs-line bg-surface">
      <span className="text-xs text-t2">{label}</span>
      <Badge className={cn("text-[10px] gap-1",
        isActive
          ? "bg-gs-green-bg text-gs-green border-transparent"
          : "bg-destructive/10 text-destructive border-destructive/20")}>
        {isActive ? <CheckCircle className="w-2.5 h-2.5" /> : <XCircle className="w-2.5 h-2.5" />}
        {isActive ? activeText : inactiveText}
      </Badge>
    </div>
  );
}

function SecurityMetric({ label, isSecure, icon }: { label: string; isSecure: boolean; icon: React.ReactNode }) {
  return (
    <div className={cn("p-2.5 rounded-gs border",
      isSecure ? "bg-gs-green-bg border-gs-green/25" : "bg-destructive/8 border-destructive/20")}>
      <div className={cn("mb-1", isSecure ? "text-gs-green" : "text-destructive")}>{icon}</div>
      <div className="text-[10px] text-t4 font-medium">{label}</div>
      <div className={cn("text-[10px] font-bold mt-0.5", isSecure ? "text-gs-green" : "text-destructive")}>
        {isSecure ? "Secure" : "Issue"}
      </div>
    </div>
  );
}

function StatusBadge({ active, trueText, falseText }: { active: boolean; trueText: string; falseText: string }) {
  return (
    <Badge className={cn("text-[10px] gap-1",
      active
        ? "bg-gs-green-bg text-gs-green border-transparent"
        : "bg-destructive/10 text-destructive border-destructive/20")}>
      {active ? <CheckCircle className="w-2.5 h-2.5" /> : <XCircle className="w-2.5 h-2.5" />}
      {active ? trueText : falseText}
    </Badge>
  );
}

function ExpiryCard({ label, date, }: { label: string; date?: string | null; }) {
  const hasDate = !!date;
  const expired = isExpired(date);
  const days = getDaysLeft(date);

  return (
    <div className={cn("p-2.5 rounded-gs border",
      !hasDate       ? "bg-surface-2 border-gs-line"
      : expired      ? "bg-destructive/8 border-destructive/20"
                     : "bg-surface border-gs-line")}>
      <div className="flex items-center justify-between mb-1">
        <span className="text-[10px] font-semibold uppercase tracking-wide text-t4">{label}</span>
        {hasDate && expired && (
          <Badge className="text-[10px] bg-destructive/10 text-destructive border-destructive/20 px-1.5 py-0">Expired</Badge>
        )}
        {hasDate && !expired && days !== null && days < 30 && (
          <Badge className="text-[10px] bg-brand-soft text-brand border-brand-border px-1.5 py-0">{days}d left</Badge>
        )}
      </div>
      <p className={cn("text-sm font-semibold",
        !hasDate ? "text-t4" : expired ? "text-destructive" : "text-t1")}>
        {formatDateTime(date)}
      </p>
    </div>
  );
}