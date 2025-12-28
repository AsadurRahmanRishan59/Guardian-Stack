import { LoginCredentials, UserResponse } from "@/types/auth.types";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { doLogin, getCurrentUser, logout } from "./auth.service";
import { toast } from "sonner";

// Query keys
export const authKeys = {
    all: ['auth'] as const,
    check: () => [...authKeys.all, 'check'] as const,
    user: () => [...authKeys.all, 'user'] as const,
};

//Get current user
export function useCurrentUser() {
    return useQuery({
        queryKey: authKeys.user(),
        queryFn: async () => {
            const response = await getCurrentUser();
            return response.data as UserResponse;
        },
        retry: 1,
        refetchOnMount: false,
        refetchOnWindowFocus: false,
        refetchOnReconnect: false,
        staleTime: Infinity

    });
}

// Login mutation
export function useLogin() {
    const queryClient = useQueryClient();
    const router = useRouter();

    return useMutation({
        mutationFn: async (credentials: LoginCredentials) => await doLogin(credentials),
        onSuccess: async (response) => {
            if (response.data?.userResponse) {
                queryClient.setQueryData(authKeys.user(), response.data.userResponse);
            }
            toast.success(response?.message || "Login successful");
            router.push('/dashboard');
        },
        onError: (error) => {
            toast.error(error.message || 'Failed to login');
        }
    });
}

// Logout mutation
export function useLogout() {
    const queryClient = useQueryClient();
    const router = useRouter();

    return useMutation({
        mutationFn: async () => await logout(),
        onSuccess: () => {
            queryClient.clear();
            router.push('/login');
        },
    });
}
