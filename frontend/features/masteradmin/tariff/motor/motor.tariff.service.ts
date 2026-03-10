// features/masteradmin/tariff/motor/motor.tariff.service.ts
import { PaginatedResponse, ServerSuccessResponse } from "@/types/common.types";
import { apiFetch } from '@/lib/api-utils';
import { MotorHierarchy, MotorTariff, MotorTariffAdminView, MotorTariffRequest } from "./motor.tariff.types";
import { MotorTariffFilterFormValues } from "./motor.tariff.schema";



//Get motor tariffs with search, sort, and filter (using query parameters)
export function getMotorTariffs(criteria?: MotorTariffFilterFormValues) {
    const params = new URLSearchParams();

    if (criteria?.tariffKey) params.append('tariffKey', criteria.tariffKey.toString());
    if (criteria?.tariffType) params.append('tariffType', criteria.tariffType);
    if (criteria?.groupOfVehicle) params.append('groupOfVehicle', criteria.groupOfVehicle);
    if (criteria?.typeOfVehicle) params.append('typeOfVehicle', criteria.typeOfVehicle);
    if (criteria?.category) params.append('category', criteria.category);
    if (typeof criteria?.isActive === 'boolean') {
        params.append('isActive', String(criteria.isActive));
    }


    if (criteria?.page !== undefined) params.append('page', criteria.page.toString());
    if (criteria?.size !== undefined) params.append('size', criteria.size.toString());
    if (criteria?.sortBy) params.append('sortBy', criteria.sortBy);
    if (criteria?.sortDirection) params.append('sortDirection', criteria.sortDirection);

    const queryString = params.toString();
    const url = queryString ? `/admin/tariffs/motor?${queryString}` : '/admin/tariffs/motor';

    return apiFetch<PaginatedResponse<MotorTariffAdminView>>(url);
}



// Get an MotorTariff by tariffKey 
export function getMotorTariffByTariffKey(tariffKey: number) {
    return apiFetch<ServerSuccessResponse<MotorTariff>>(`/admin/tariffs/motor/${tariffKey}`);
}

// POST: Create MotorTariff
export function createMotorTariff(data: MotorTariffRequest) {
    return apiFetch<ServerSuccessResponse<MotorTariffRequest>>('/admin/tariffs/motor', {
        method: 'POST',
        body: JSON.stringify(data),
    });
}

// PUT: Update MotorTariff
export function updateMotorTariff(tariffKey: number, data: MotorTariffRequest) {
    return apiFetch<ServerSuccessResponse<MotorTariffRequest>>(`/admin/tariffs/motor/${tariffKey}`, {
        method: 'PUT',
        body: JSON.stringify(data),
    });
}

// PATCH: Update MotorTariff rates
export function patchMotorTariffRates(tariffKey: number, data: Partial<MotorTariffRequest>) {
    return apiFetch<ServerSuccessResponse<MotorTariff>>(
        `/admin/tariffs/motor/${tariffKey}/rates`,
        {
            method: 'PATCH',
            body: JSON.stringify(data),
        }
    );
}


// Delete MotorTariff
export function deleteMotorTariff(tariffKey: number) {
    return apiFetch<ServerSuccessResponse<null>>(`/admin/tariffs/motor/${tariffKey}`, {
        method: 'DELETE',
    });
}


export function getMotorHierarchy(criteria: MotorHierarchy) {
    const params = new URLSearchParams();

    if (criteria?.level) params.append('level', criteria.level.toString());
    if (criteria?.tariffType) params.append('tariffType', criteria.tariffType);
    if (criteria?.groupOfVehicle) params.append('groupOfVehicle', criteria.groupOfVehicle);
    if (criteria?.typeOfVehicle) params.append('typeOfVehicle', criteria.typeOfVehicle);

    const queryString = params.toString();
    const url = `/admin/tariffs/motor/hierarchy?${queryString}`;
    return apiFetch<ServerSuccessResponse<string[]>>(url);
}