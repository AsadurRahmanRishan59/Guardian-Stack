// useQueryBankBranch.ts - Query hook only
import { useQuery } from "@tanstack/react-query";
import { getRoles } from "./role.service";
import { Role } from "@/types/auth.types";


export function useQueryGetRoles() {
    const { data, isLoading, error, refetch } = useQuery({
        queryKey: ['roles'],
        queryFn: async () => await getRoles()
        ,
        staleTime: 5 * 60 * 1000, // 5 minutes
        gcTime: 10 * 60 * 1000, // 10 minutes
        refetchOnWindowFocus: false,
        retry: 3,
        retryDelay: attemptIndex => Math.min(1000 * 2 ** attemptIndex, 30000)
    });
    const roles = data?.data as Role || [];
    return {
        roles ,
        isLoading,
        error,
        refetch
    };
}