// components/ProtectedRoute.tsx
// Component to protect routes based on authentication and roles

'use client';

import { useRouter } from 'next/navigation';
import { useCurrentUser } from '@/lib/hooks/useAuth';
import { UserRole } from '@/types/auth.types';
import { useEffect } from 'react';

interface ProtectedRouteProps {
  children: React.ReactNode;
  requiredRoles?: UserRole[];
  requireAll?: boolean; // If true, user must have ALL roles
  fallbackUrl?: string;
}

export default function ProtectedRoute({
  children,
  requiredRoles = [],
  requireAll = false,
  fallbackUrl = '/unauthorized',
}: ProtectedRouteProps) {
  const router = useRouter();
  const { data: user, isLoading, isError } = useCurrentUser();

  useEffect(() => {
    // Not authenticated
    if (isError || (!isLoading && !user)) {
      // router.push('/signin');
      return;
    }

    // Authenticated but checking roles
    if (!isLoading && user && requiredRoles.length > 0) {
      const userHasAccess = requireAll
        ? requiredRoles.every(role => user.roles.includes(role))
        : requiredRoles.some(role => user.roles.includes(role));

      if (!userHasAccess) {
        // router.push(fallbackUrl);
      }
    }
  }, [user, isLoading, isError, requiredRoles, requireAll, fallbackUrl, router]);

  // Show loading state
  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="inline-block animate-spin rounded-full h-12 w-12 border-b-2 border-gray-900"></div>
          <p className="mt-4 text-gray-600">Loading...</p>
        </div>
      </div>
    );
  }

  // Not authenticated
  if (!user) {
    return null;
  }

  // Check role access
  if (requiredRoles.length > 0) {
    const userHasAccess = requireAll
      ? requiredRoles.every(role => user.roles.includes(role))
      : requiredRoles.some(role => user.roles.includes(role));

    if (!userHasAccess) {
      return null;
    }
  }

  return <>{children}</>;
}