// lib/utils/role-check.ts

import { AppRole } from "@/types/auth.types";
import { NavigationSection } from "../navigation-config";
import { useCurrentUser } from "@/features/auth/auth.react.query";



/**
 * Check if user has at least one of the required roles
 */
export function hasRequiredRole(
  userRoles: AppRole[],
  requiredRoles: AppRole[]
): boolean {
     
  if (!requiredRoles || requiredRoles.length === 0) {
    return true; // No role requirement means accessible to all
  }
  return userRoles.some(role => requiredRoles.includes(role));
}

export function useHasRole(requiredRole: AppRole | AppRole[]) {
  const { data: user, isLoading,error } = useCurrentUser();

  const hasRole = () => {
    if (!user?.roles) return false;

    const roles = Array.isArray(requiredRole) ? requiredRole : [requiredRole];
    return roles.some(role => user.roles.includes(role));
  };

  return {
    hasRole: hasRole(),
    user,
    isLoading,
    error
  };
}


/**
 * Check if user has required role (doesn't redirect)
 */
// export function hasRequiredRole(userRoles: UserRole[], requiredRoles: UserRole[]): boolean {
//   if (!requiredRoles || requiredRoles.length === 0) {
//     return true;
//   }
//   return userRoles.some(role => requiredRoles.includes(role));
// }


/**
 * Filter navigation items based on user roles
 */
export function filterNavigationByRole(
  sections: NavigationSection[],
  userRoles: AppRole[]
): NavigationSection[] {
  return sections
    .filter(section => hasRequiredRole(userRoles, section.roles))
    .map(section => ({
      ...section,
      navMain: section.navMain.filter(item =>
        hasRequiredRole(userRoles, item.roles)
      ),
    }))
    .filter(section => section.navMain.length > 0); // Remove empty sections
}

/**
 * Get current user from server-side session
 * This should integrate with your actual auth system
 */
// export async function getCurrentUser(): Promise<User | null> {
//   try {
//     const cookieStore = await cookies();
//     const session = cookieStore.get('user-session');
    
//     if (!session) {
//       return null;
//     }

//     // Parse user from session cookie
//     const user = JSON.parse(session.value);
//     return user;
//   } catch (error) {
//     console.error('Failed to get current user:', error);
//     return null;
//   }
// }

/**
 * Require authentication - redirects to login if not authenticated
 */
// export async function requireAuth(): Promise<User> {
//   const user = await getCurrentUser();
  
//   if (!user) {
//     redirect('/signin');
//   }
  
//   return user;
// }

/**
 * Require specific roles - redirects to unauthorized if user doesn't have required roles
 */
// export async function requireRoles(requiredRoles: UserRole[]): Promise<User> {
//   const user = await requireAuth();
  
//   const hasRole = user.roles.some(role => requiredRoles.includes(role));
  
//   if (!hasRole) {
//     redirect('/unauthorized');
//   }
  
//   return user;
// }

