// components/Navbar.tsx
// Navigation bar with role-based menu items

'use client';

import Link from 'next/link';
import { useCurrentUser, useLogout } from '@/lib/hooks/useAuth';
import { RoleGuard } from '@/components/RoleGuard';
import { AppRole } from '@/types/auth.types';

export default function Navbar() {
  const { data: user, isLoading } = useCurrentUser();
  const logoutMutation = useLogout();

  const handleLogout = async () => {
    if (confirm('Are you sure you want to logout?')) {
      await logoutMutation.mutateAsync();
    }
  };

  if (isLoading) {
    return (
      <nav className="bg-white shadow-md">
        <div className="container mx-auto px-6 py-4">
          <div className="animate-pulse flex space-x-4">
            <div className="h-8 bg-gray-200 rounded w-32"></div>
          </div>
        </div>
      </nav>
    );
  }

  if (!user) {
    return null;
  }

  return (
    <nav className="bg-white shadow-md">
      <div className="container mx-auto px-6 py-4">
        <div className="flex items-center justify-between">
          {/* Logo */}
          <div className="flex items-center space-x-8">
            <Link href="/dashboard" className="text-xl font-bold text-gray-800">
              Voucher System
            </Link>

            {/* Navigation Links */}
            <div className="hidden md:flex space-x-4">
              <Link
                href="/dashboard"
                className="text-gray-600 hover:text-gray-800 px-3 py-2 rounded-md text-sm font-medium"
              >
                Dashboard
              </Link>

              {/* Vouchers - Account Manager & Account User */}
              <RoleGuard requiredRoles={[AppRole.ACCOUNT_MANAGER, AppRole.ACCOUNT_USER]}>
                <Link
                  href="/vouchers"
                  className="text-gray-600 hover:text-gray-800 px-3 py-2 rounded-md text-sm font-medium"
                >
                  Vouchers
                </Link>
              </RoleGuard>

              {/* Account Manager Page - Account Manager only */}
              <RoleGuard requiredRoles={AppRole.ACCOUNT_MANAGER}>
                <Link
                  href="/account-manager"
                  className="text-gray-600 hover:text-gray-800 px-3 py-2 rounded-md text-sm font-medium"
                >
                  Manager Panel
                </Link>
              </RoleGuard>

              {/* Admin Page - Admin only */}
              <RoleGuard requiredRoles={AppRole.ADMIN}>
                <Link
                  href="/admin"
                  className="text-gray-600 hover:text-gray-800 px-3 py-2 rounded-md text-sm font-medium"
                >
                  Admin Panel
                </Link>
              </RoleGuard>
            </div>
          </div>

          {/* User Menu */}
          <div className="flex items-center space-x-4">
            <div className="text-sm text-gray-600">
              <span className="font-medium">{user.username}</span>
              <div className="flex gap-1 mt-1">
                {user.roles.map(role => (
                  <span
                    key={role}
                    className="px-2 py-0.5 bg-blue-100 text-blue-800 rounded text-xs"
                  >
                    {role.replace('ROLE_', '')}
                  </span>
                ))}
              </div>
            </div>

            <button
              onClick={handleLogout}
              disabled={logoutMutation.isPending}
              className="px-4 py-2 bg-red-500 text-white rounded hover:bg-red-600 text-sm font-medium disabled:bg-gray-400"
            >
              {logoutMutation.isPending ? 'Logging out...' : 'Logout'}
            </button>
          </div>
        </div>
      </div>
    </nav>
  );
}