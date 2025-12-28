import { api } from "@/lib/api.client";
import { ApiResponse } from "@/types/api.types";
import { AdminUserCreateRequestDTO, AdminUserResponseDTO, AdminUserUpdateRequestDTO, AdminUserView, AdminUserViewFilterOptions, AdminUserViewSearchCriteria } from "./user.types";


export function getAllUsers(searchCriteria?: AdminUserViewSearchCriteria): Promise<ApiResponse<AdminUserView>> {
    return api.client.get('/admin/user', searchCriteria);
}

export function getUserById(userId:number): Promise<ApiResponse<AdminUserResponseDTO>> {
    return api.client.get(`/admin/user/${userId}`);
}

export function createUser(adminUserCreateRequestDTO: AdminUserCreateRequestDTO): Promise<ApiResponse<AdminUserResponseDTO>> {
    return api.client.post('/admin/user', adminUserCreateRequestDTO);
}

export function updateUserById(adminUserUpdateRequestDTO:AdminUserUpdateRequestDTO,userId:number): Promise<ApiResponse<AdminUserResponseDTO>> {
    return api.client.put(`/admin/user/${userId}`,adminUserUpdateRequestDTO);
}

export function getAdminUserViewFilterOptions(): Promise<ApiResponse<AdminUserViewFilterOptions>> {
    return api.client.get('/admin/user/filter-options');
}
