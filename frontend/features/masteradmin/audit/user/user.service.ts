// features/masteradmin/audit/user/user.service.ts
import { api } from "@/lib/api.client";
import { ApiResponse } from "@/types/api.types";
import { AuditFilterRequest, MasterAdminUserAuditDTO } from "./user.types";

export function getAuditHistory(searchCriteria?: AuditFilterRequest): Promise<ApiResponse<MasterAdminUserAuditDTO>> {
    return api.client.get('/master-admin/audit/users', searchCriteria as Record<string, string | number | boolean | null | undefined>);
}

export function getUserAuditHistory(userId: number): Promise<ApiResponse<MasterAdminUserAuditDTO>> {
    return api.client.get(`/master-admin/audit/users/${userId}`);
}

export function getRevisionSnapshot(userId: number, revisionNumber: number): Promise<ApiResponse<MasterAdminUserAuditDTO>> {
    return api.client.get(`/master-admin/audit/users/${userId}/revision/${revisionNumber}`);
}