import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import { createMotorTariff, deleteMotorTariff, getMotorHierarchy, getMotorTariffByTariffKey, getMotorTariffs, patchMotorTariffRates, updateMotorTariff } from './motor.tariff.service';
import { MotorTariffRequest, MotorTariff } from './motor.tariff.types';
import { MotorTariffFilterFormValues } from './motor.tariff.schema';
import { useMemo } from 'react';


// Enhanced hook for paginated motorTariffs with search/filter
export function useQueryMotorTariffs(searchCriteria?: MotorTariffFilterFormValues) {
    const { data, isLoading, error, refetch } = useQuery({
        queryKey: ['motorTariffs', 'paginated', { criteria: searchCriteria }],
        queryFn: async () => {
            const response = await getMotorTariffs(searchCriteria);
            return response ?? null; // return full response (including data + pagination)
        },
        staleTime: 5 * 60 * 1000,
        refetchOnWindowFocus: false,
        retry: 3,
        retryDelay: attemptIndex => Math.min(1000 * 2 ** attemptIndex, 30000),
    });

    return {
        motorTariffs: data?.data || [],
        pagination: {
            currentPage: data?.pagination?.currentPage || 0,
            pageSize: data?.pagination?.pageSize || 10,
            totalElements: data?.pagination?.totalElements || 0,
            totalPages: data?.pagination?.totalPages || 0,
            hasNext: data?.pagination?.hasNext ?? false,
            hasPrevious: data?.pagination?.hasPrevious ?? false,
            sortBy: data?.pagination?.sortBy || "tariffKey",
            sortDirection: data?.pagination?.sortDirection || "asc"
        },
        isLoading,
        error,
        refetch,
    };
}



//Get MotorTariff by tariffKey
export function useGetMotorTariffByTariffKey(tariffKey?: number) {
    return useQuery<MotorTariff | null>({
        queryKey: ["motorTariff", tariffKey],
        queryFn: async () => {
            if (!tariffKey) return null
            const response = await getMotorTariffByTariffKey(tariffKey)
            return response?.data || null
        },
        enabled: !!tariffKey,
        staleTime: 0,
    })
}

// Create motorTariff mutation
export function useCreateMotorTariff() {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: async (motorTariffRequest: MotorTariffRequest) => {
            const response = await createMotorTariff(motorTariffRequest);
            return response;
        },
        onSuccess: (response) => {
            // Invalidate all motorTariff-related queries
            queryClient.invalidateQueries({ queryKey: ['motorTariffs'] });
            toast.success(response?.message || "MotorTariff created successfully");
        },
        onError: (error) => {
            toast.error(error.message || 'Failed to create motorTariff');
        }
    });
}

// Update motorTariff mutation
export function useUpdateMotorTariff() {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: async ({ tariffKey, motorTariffRequest }: { tariffKey: number, motorTariffRequest: MotorTariffRequest }) =>
            await updateMotorTariff(tariffKey, motorTariffRequest),

        onSuccess: (response, { tariffKey }) => {
            // Invalidate all motorTariff-related queries
            queryClient.invalidateQueries({ queryKey: ['motorTariffs'] });
            // Optionally update the specific motorTariff in cache
            queryClient.invalidateQueries({ queryKey: ['motorTariff', tariffKey] });
            toast.success(response?.message || 'MotorTariff updated successfully');
        },
        onError: (error) => {
            toast.error(error.message || 'Failed to update motorTariff');
        }
    });
}

// Patch MotorTariff rates mutation
export function usePatchMotorTariffRates() {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: async ({
            tariffKey,
            rates,
        }: {
            tariffKey: number;
            rates: Partial<MotorTariffRequest>;
        }) => {
            return await patchMotorTariffRates(tariffKey, rates);
        },
        onSuccess: (response, { tariffKey }) => {
            // Refresh the list
            queryClient.invalidateQueries({ queryKey: ['motorTariffs'] });
            // Refresh the specific tariff
            queryClient.invalidateQueries({ queryKey: ['motorTariff', tariffKey] });

            toast.success(
                response?.message || `Rates updated successfully for tariff ${tariffKey}`
            );
        },
        onError: (error) => {
            toast.error(error.message || 'Failed to update MotorTariff rates');
        },
    });
}



// Delete motorTariff mutation
export function useDeleteMotorTariff() {
    const queryClient = useQueryClient();

    return useMutation({
        mutationFn: async (tariffKey: number) => {
            await deleteMotorTariff(tariffKey);
            return tariffKey;
        },
        onSuccess: (tariffKey) => {
            // Invalidate all motorTariff-related queries
            queryClient.invalidateQueries({ queryKey: ['motorTariffs'] });
            // Remove the specific motorTariff from cache
            queryClient.removeQueries({ queryKey: ['motorTariff', 'id', tariffKey] });

            toast.success('MotorTariff deleted successfully');
        },
        onError: (error) => {
            toast.error(error.message || 'Failed to delete motorTariff');
        }
    });
}

//Get Motor Hierarchy
export function useMotorHierarchyLevel(
    level: 'tariffType' | 'groupOfVehicle' | 'typeOfVehicle' | 'category',
    filters: { tariffType?: string; groupOfVehicle?: string; typeOfVehicle?: string }
) {
    const params = useMemo(() => {
        const p: Record<string, string> = { level };

        if (level !== 'tariffType' && filters.tariffType) {
            p.tariffType = filters.tariffType;
        }
        if (['typeOfVehicle', 'category'].includes(level) && filters.groupOfVehicle) {
            p.groupOfVehicle = filters.groupOfVehicle;
        }
        if (level === 'category' && filters.typeOfVehicle) {
            p.typeOfVehicle = filters.typeOfVehicle;
        }

        return p;
    }, [level, filters.tariffType, filters.groupOfVehicle, filters.typeOfVehicle]);

    const enabled = (() => {
        if (level === 'tariffType') return true;
        if (level === 'groupOfVehicle') return Boolean(params.tariffType);
        if (level === 'typeOfVehicle') return Boolean(params.tariffType && params.groupOfVehicle);
        if (level === 'category') return Boolean(params.tariffType && params.groupOfVehicle && params.typeOfVehicle);
        return false;
    })();

    return useQuery({
        queryKey: ['motorHierarchy', level, params],
        queryFn: () => getMotorHierarchy(params),
        // staleTime: 600000,
        enabled,
    });
}