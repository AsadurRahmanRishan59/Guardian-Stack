import { api } from "@/lib/api.client";
import { ApiResponse } from "@/types/api.types";
import { AdminUserCreateRequestDTO, AdminUserUpdateRequestDTO, MasterAdminUserDTO, MasterAdminUserViewFilterOptions, MasterAdminUserView, MasterAdminUserViewSearchCriteria, } from "./user.types";


export function getAllUsers(searchCriteria?: MasterAdminUserViewSearchCriteria): Promise<ApiResponse<MasterAdminUserView>> {
    return api.client.get('/master-admin/user', searchCriteria as Record<string, string | number | boolean | null | undefined>);
}

export function getUserById(userId: number): Promise<ApiResponse<MasterAdminUserDTO>> {
    return api.client.get(`/master-admin/user/${userId}`);
}

export function createUser(adminUserCreateRequestDTO: AdminUserCreateRequestDTO): Promise<ApiResponse<MasterAdminUserDTO>> {
    return api.client.post('/master-admin/user', adminUserCreateRequestDTO);
}

export function updateUserById(adminUserUpdateRequestDTO: AdminUserUpdateRequestDTO, userId: number): Promise<ApiResponse<MasterAdminUserDTO>> {
    return api.client.put(`/master-admin/user/${userId}`, adminUserUpdateRequestDTO);
}

export function getAdminUserViewFilterOptions(): Promise<ApiResponse<MasterAdminUserViewFilterOptions>> {
    return api.client.get('/master-admin/user/filter-options');
}
