"use client";

// components/RoleGuard.tsx
//
// ✅ Reads from UserContext — does NOT call useCurrentUser().
// Role check is pure synchronous logic — no extra network requests.

import { useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import { Loader2 } from "lucide-react";
import { AppRole } from "@/types/auth.types";
import { useUser } from "@/app/(authenticated)/layout";

interface RoleGuardProps {
  children:      React.ReactNode;
  requiredRoles: AppRole | AppRole[];
  fallback?:     React.ReactNode;
}

export function RoleGuard({
  children,
  requiredRoles,
  fallback = null,
}: RoleGuardProps) {
  const router      = useRouter();
  const { user, isLoading } = useUser(); // ← context, not useCurrentUser()
  const redirecting = useRef(false);

  // Normalise to array
  const required = Array.isArray(requiredRoles) ? requiredRoles : [requiredRoles];

  // Synchronous role check — no hook, no query
  const hasRole = !!user?.roles?.some((r) => required.includes(r as AppRole));

  useEffect(() => {
    if (isLoading) return;
    if (user && !hasRole && !redirecting.current) {
      redirecting.current = true;
      router.replace("/unauthorized");
    }
  }, [user, hasRole, isLoading, router]);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-[200px]">
        <Loader2 className="w-5 h-5 animate-spin text-t4" />
      </div>
    );
  }

  if (!user || !hasRole) return <>{fallback}</>;

  return <>{children}</>;
}