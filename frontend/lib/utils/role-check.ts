// lib/utils/role-check.ts
//
// ✅ useHasRole reads from UserContext — no useCurrentUser() call.
// filterNavigationByRole is pure — no hooks, safe to call anywhere.

import { useUser } from "@/app/(authenticated)/layout";
import { AppRole } from "@/types/auth.types";
import type { NavigationSection } from "@/lib/navigation-config";

// ─── Hook ─────────────────────────────────────────────────────────────────────

/**
 * Returns whether the current user has at least one of the required roles.
 * Reads from UserContext — fires zero network requests.
 */
export function useHasRole(requiredRoles: AppRole | AppRole[]): {
  hasRole:   boolean;
  isLoading: boolean;
  error:     null; // never errors — context is always available
} {
  const { user, isLoading } = useUser();

  const required = Array.isArray(requiredRoles) ? requiredRoles : [requiredRoles];
  const hasRole  = !!user?.roles?.some((r) => required.includes(r as AppRole));

  return { hasRole, isLoading, error: null };
}

// ─── Pure utility ─────────────────────────────────────────────────────────────

/**
 * Filters navigation config to only sections/items the user's roles allow.
 * Pure function — no hooks, safe to use in useMemo.
 */
export function filterNavigationByRole(
  config: NavigationSection[],
  userRoles: string[]
): NavigationSection[] {
  return config
    .filter((section) =>
      section.roles.some((r) => userRoles.includes(r))
    )
    .map((section) => ({
      ...section,
      navMain: filterNavItems(section.navMain, userRoles),
    }))
    .filter((section) => section.navMain.length > 0);
}

function filterNavItems(
  items: NavigationSection["navMain"],
  userRoles: string[]
): NavigationSection["navMain"] {
  return items
    .filter((item) => item.roles.some((r) => userRoles.includes(r)))
    .map((item) => ({
      ...item,
      items: item.items
        ? filterNavItems(item.items, userRoles)
        : undefined,
    }));
}