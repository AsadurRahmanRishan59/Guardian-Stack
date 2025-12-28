// lib/utils/permission-utils.ts
// Utility functions for permission checking

import { AppRole } from '@/types/auth.types';

export const hasRole = (AppRoles: AppRole[], requiredRole: AppRole | AppRole[]): boolean => {
  const roles = Array.isArray(requiredRole) ? requiredRole : [requiredRole];
  return roles.some(role => AppRoles.includes(role));
};

export const hasAllRoles = (AppRoles: AppRole[], requiredRoles: AppRole[]): boolean => {
  return requiredRoles.every(role => AppRoles.includes(role));
};

export const isAdmin = (AppRoles: AppRole[]): boolean => {
  return AppRoles.includes(AppRole.ADMIN);
};

export const isAccountManager = (AppRoles: AppRole[]): boolean => {
  return AppRoles.includes(AppRole.ACCOUNT_MANAGER);
};

export const isAccountUser = (AppRoles: AppRole[]): boolean => {
  return AppRoles.includes(AppRole.ACCOUNT_USER);
};

export const canAccessVouchers = (AppRoles: AppRole[]): boolean => {
  return hasRole(AppRoles, [AppRole.ACCOUNT_MANAGER, AppRole.ACCOUNT_USER]);
};

export const canDeleteVoucher = (AppRoles: AppRole[]): boolean => {
  return hasRole(AppRoles, [AppRole.ADMIN, AppRole.ACCOUNT_MANAGER]);
};

export const canCreateVoucher = (AppRoles: AppRole[]): boolean => {
  return hasRole(AppRoles, [AppRole.ADMIN, AppRole.ACCOUNT_MANAGER]);
};
