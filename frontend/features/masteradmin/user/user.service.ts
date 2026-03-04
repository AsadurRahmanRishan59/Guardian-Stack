// features/masteradmin/user/user.service.ts
import { api } from "@/lib/api.client";
import { ApiResponse } from "@/types/api.types";
import { MasterAdminUserCreateRequestDTO, MasterAdminUserUpdateRequestDTO, MasterAdminUserDTO, MasterAdminUserViewFilterOptions, MasterAdminUserView, MasterAdminUserViewSearchCriteria, } from "./user.types";


export function getAllUsers(searchCriteria?: MasterAdminUserViewSearchCriteria): Promise<ApiResponse<MasterAdminUserView>> {
    return api.client.get('/master-admin/user', searchCriteria as Record<string, string | number | boolean | null | undefined>);
}

export function getUserById(userId: number): Promise<ApiResponse<MasterAdminUserDTO>> {
    return api.client.get(`/master-admin/user/${userId}`);
}

export function createUser(dto: MasterAdminUserCreateRequestDTO): Promise<ApiResponse<void>> {
    return api.client.post('/master-admin/user', dto);
}

export function updateUserById(dto: MasterAdminUserUpdateRequestDTO, userId: number): Promise<ApiResponse<void>> {
    return api.client.put(`/master-admin/user/${userId}`, dto);
}

export function getAdminUserViewFilterOptions(): Promise<ApiResponse<MasterAdminUserViewFilterOptions>> {
    return api.client.get('/master-admin/user/filter-options');
}
