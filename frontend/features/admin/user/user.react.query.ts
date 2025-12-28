// features/admin/user/user.react.query.ts
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AdminUserCreateRequestDTO, AdminUserUpdateRequestDTO, AdminUserView, AdminUserViewSearchCriteria } from "./user.types";
import { createUser, getAdminUserViewFilterOptions, getAllUsers, getUserById, updateUserById } from "./user.service";
import { toast } from "sonner";

// Hook for paginated users with search/filter
export function useQueryAdminUserView(searchCriteria?: AdminUserViewSearchCriteria) {
    const { data, isLoading, error, refetch } = useQuery({
        queryKey: ['adminUserView', 'paginated', { criteria: searchCriteria }],
        queryFn: async () => {
            const response = await getAllUsers(searchCriteria);
            return response ?? null;
        },
        staleTime: 5 * 60 * 1000,
        refetchOnWindowFocus: false,
        retry: 3,
        retryDelay: attemptIndex => Math.min(1000 * 2 ** attemptIndex, 30000),
    });
    // Explicitly type the users as an array
    const users: AdminUserView[] = Array.isArray(data?.data) ? data.data : [];
    return {
        users,
        pagination: {
            currentPage: data?.pagination?.currentPage || 0,
            pageSize: data?.pagination?.pageSize || 10,
            totalElements: data?.pagination?.totalElements || 0,
            totalPages: data?.pagination?.totalPages || 0,
            hasNext: data?.pagination?.hasNext ?? false,
            hasPrevious: data?.pagination?.hasPrevious ?? false,
            sortBy: data?.pagination?.sortBy || "username",
            sortDirection: data?.pagination?.sortDirection || "asc"
        },
        isLoading,
        error,
        refetch,
    };
}

//Get User by userId
export function useGetUserById(userId?: number) {
    return useQuery({
        queryKey: ["user", userId],
        queryFn: async () => {
            if (!userId) return null
            const response = await getUserById(userId)
            return response?.data || null
        },
        enabled: !!userId,
        staleTime: 0,
    })
}


// Create user mutation
export function useCreateUser() {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: async (user: AdminUserCreateRequestDTO) => {
            const response = await createUser(user);
            return response;
        },
        onSuccess: (response) => {
            // Invalidate all agent-related queries
            queryClient.invalidateQueries({ queryKey: ['adminUserView'] });
            toast.success(response?.message || "User created successfully");
        },
        onError: (error) => {
            toast.error(error.message || 'Failed to create user');
        }
    });
}

// Update user mutation
export function useUpdateUser() {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: async (params: { user: AdminUserUpdateRequestDTO, userId: number }) => {
            const { user, userId } = params;
            const response = await updateUserById(user, userId);
            return response;
        },
        onSuccess: (response) => {
            // Invalidate all user-related queries
            queryClient.invalidateQueries({ queryKey: ['adminUserView'] });
            toast.success(response?.message || "User updated successfully");
        },
        onError: (error) => {
            toast.error(error.message || 'Failed to update user');
        }
    });
}

export function useQueryAdminUserViewFilterOptions() {
    const {
        data,
        isLoading,
        error,
        refetch,
    } = useQuery({
        queryKey: ["adminUserView", "filter-options"],
        queryFn: async () => {
            const response = await getAdminUserViewFilterOptions();
            return response.data ?? null;

        },
        staleTime: 10 * 60 * 1000,
        refetchOnWindowFocus: false,
        retry: 3,
    });

    return {
        filterOptions: data,
        isLoading,
        error,
        refetch,
    };
}

