'use client';

import { useHasRole } from '@/lib/utils/role-check';
import { AppRole } from '@/types/auth.types';
import { useRouter } from 'next/navigation';
import { useEffect } from 'react';
import { Loader2 } from 'lucide-react';

interface RoleGuardProps {
  children: React.ReactNode;
  requiredRoles: AppRole | AppRole[];
  fallback?: React.ReactNode; // optional custom fallback
}

export function RoleGuard({
  children,
  requiredRoles,
  fallback = null,
}: RoleGuardProps) {
  const router = useRouter();
  const { hasRole, isLoading, error } = useHasRole(requiredRoles);

  // Redirect if user has no role
  useEffect(() => {
    if (!isLoading && !hasRole && !error) {
      router.replace('/unauthorized'); // unauthorized page
    }
  }, [hasRole, isLoading, error, router]);

  // Loading placeholder (spinner)
  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-[200px]">
        <Loader2 className="w-6 h-6 animate-spin text-muted-foreground dark:text-muted-foreground" />
      </div>
    );
  }

  // Show error if exists
  if (error) {
    return (
      <div className="p-4 border rounded-md bg-destructive/10 text-destructive dark:bg-destructive/20 dark:text-destructive">
        <p className="font-semibold">Error:</p>
        <p>{(error as Error).message || 'Something went wrong'}</p>
      </div>
    );
  }

  // If user has role, render children
  if (hasRole) {
    return <>{children}</>;
  }

  // fallback if provided
  return <>{fallback}</>;
}
