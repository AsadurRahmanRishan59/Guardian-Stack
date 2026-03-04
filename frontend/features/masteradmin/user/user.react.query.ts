// features/masteradmin/user/user.react.query.ts
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { MasterAdminUserCreateRequestDTO, MasterAdminUserUpdateRequestDTO, MasterAdminUserView, MasterAdminUserViewSearchCriteria, } from "./user.types";
import { createUser, getAdminUserViewFilterOptions, getAllUsers, getUserById, updateUserById } from "./user.service";
import { toast } from "sonner";

// ─── List ─────────────────────────────────────────────────────────────────────

export function useQueryAdminUserView(searchCriteria?: MasterAdminUserViewSearchCriteria) {
    const { data, isLoading, error, refetch } = useQuery({
        queryKey: ['masterAdminUserView', 'paginated', { criteria: searchCriteria }],
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
    const users: MasterAdminUserView[] = Array.isArray(data?.data) ? data.data : [];
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

// ─── Single user ──────────────────────────────────────────────────────────────

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


// ─── Create ───────────────────────────────────────────────────────────────────

export function useCreateUser() {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: (dto: MasterAdminUserCreateRequestDTO) => createUser(dto),
        onSuccess: (res) => {
            queryClient.invalidateQueries({ queryKey: ["masterAdminUserView"] });
            toast.success(res?.message ?? "User created successfully");
        },
        onError: (err: Error) => {
            toast.error(err.message ?? "Failed to create user");
        },
    });
}

// ─── Update ───────────────────────────────────────────────────────────────────

export function useUpdateUser() {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: ({
            dto,
            userId,
        }: {
            dto: MasterAdminUserUpdateRequestDTO;
            userId: number;
        }) => updateUserById(dto, userId),
        onSuccess: (res, { userId }) => {
            queryClient.invalidateQueries({ queryKey: ["masterAdminUserView"] });
            queryClient.invalidateQueries({ queryKey: ["masterAdminUser", userId] });
            toast.success(res?.message ?? "User updated successfully");
        },
        onError: (err: Error) => {
            toast.error(err.message ?? "Failed to update user");
        },
    });
}

// ─── Filter options ───────────────────────────────────────────────────────────

export function useQueryAdminUserViewFilterOptions() {
    const { data, isLoading, error, refetch } = useQuery({
        queryKey: ["masterAdminUserView", "filter-options"],
        queryFn: getAdminUserViewFilterOptions,
        staleTime: 10 * 60 * 1000,
        refetchOnWindowFocus: false,
        retry: 3,
    });

    return {
        filterOptions: data?.data ?? null,
        isLoading,
        error,
        refetch,
    };
}
