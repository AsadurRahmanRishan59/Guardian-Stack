import { api } from "@/lib/api.client";
import { ApiResponse } from "@/types/api.types";
import { Role } from "@/types/auth.types";


export function getRoles(): Promise<ApiResponse<Role>> {
    return api.client.get('/admin/roles');
}
