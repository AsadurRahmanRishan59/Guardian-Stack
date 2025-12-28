// lib/hooks/useAuth.ts
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useRouter } from 'next/navigation';
import { authService } from '@/lib/api/auth.service';
import { LoginCredentials, UserResponse, AppRole } from '@/types/auth.types';

// Query keys
export const authKeys = {
  all: ['auth'] as const,
  check: () => [...authKeys.all, 'check'] as const,
  user: () => [...authKeys.all, 'user'] as const,
};

// Get current user with roles
// lib/hooks/useAuth.ts
export function useCurrentUser() {
  return useQuery({
    queryKey: authKeys.user(),
    queryFn: async () => {
      try {
        const response = await authService.getCurrentUser();
        console.log('✅ useCurrentUser fetched:', response.data);
        return response.data as UserResponse;
      } catch (error) {
        console.log('❌ useCurrentUser error:', error);
        return null;
      }
    },
    retry: 1,
    staleTime: Infinity,
    refetchOnWindowFocus: false,
    refetchOnMount: 'always', // This is important!
    refetchOnReconnect: false,
    // Add these to prevent premature redirects:
    initialData: undefined, // Explicitly set undefined initially
    placeholderData: undefined,
  });
}

// Check if user has specific role
export function useHasRole(requiredRole: AppRole | AppRole[]) {
  const { data: user, isLoading } = useCurrentUser();

  const hasRole = () => {
    if (!user?.roles) return false;

    const roles = Array.isArray(requiredRole) ? requiredRole : [requiredRole];
    return roles.some(role => user.roles.includes(role));
  };

  return {
    hasRole: hasRole(),
    user,
    isLoading,
  };
}

// Check if user has ALL specified roles
export function useHasAllRoles(requiredRoles: AppRole[]) {
  const { data: user, isLoading } = useCurrentUser();

  const hasAllRoles = () => {
    if (!user?.roles) return false;
    return requiredRoles.every(role => user.roles.includes(role));
  };

  return {
    hasAllRoles: hasAllRoles(),
    user,
    isLoading,
  };
}

// Check if user is admin
export function useIsAdmin() {
  return useHasRole(AppRole.ADMIN);
}

// Login mutation - FIXED to properly set user data
export function useLogin() {
  const queryClient = useQueryClient();
  const router = useRouter();

  return useMutation({
    mutationFn: async (credentials: LoginCredentials) => {
      const response = await authService.login(credentials);
      return response;
    },
    onSuccess: async (response) => {
      // CRITICAL: Set user data in cache immediately
      if (response.data?.userResponse) {
        queryClient.setQueryData(authKeys.user(), response.data.userResponse);
      }

      // Wait for cookies to be set
      await new Promise(resolve => setTimeout(resolve, 100));

      // Fetch user data to confirm
      try {
        const userResponse = await authService.getCurrentUser();
        queryClient.setQueryData(authKeys.user(), userResponse.data);
      } catch (error) {
        console.error('Failed to fetch user after login:', error);
      }

      // Now redirect
      router.push('/dashboard');
    },
    onError: (error) => {
      console.error('Login error:', error);
    },
  });
}

// Logout mutation
export function useLogout() {
  const queryClient = useQueryClient();
  const router = useRouter();

  return useMutation({
    mutationFn: async () => {
      try {
        await authService.logout();
      } catch (error) {
        console.error('Logout error:', error);
      }
    },
    onSuccess: () => {
      // Clear all queries
      queryClient.clear();
      
      // Redirect to login
      router.push('/login');
    },
  });
}