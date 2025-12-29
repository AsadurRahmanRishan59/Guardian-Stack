import { api } from "@/lib/api.client";
import { ApiResponse } from "@/types/api.types";
import { LoginCredentials, LoginResponseDTO, SignupRequest, UserResponse } from "@/types/auth.types";

export function doSignup(signupRequest: SignupRequest): Promise<ApiResponse<LoginResponseDTO>> {
    return api.client.post('/auth/login', signupRequest);
}

export function doLogin(credentials: LoginCredentials): Promise<ApiResponse<LoginResponseDTO>> {
    return api.client.post('/auth/login', credentials);
}

export function logout(): Promise<ApiResponse<null>> {
    return api.client.post<null>('/auth/logout');
}

export function getCurrentUser(): Promise<ApiResponse<UserResponse>> {
    return api.client.get('/auth/me');
}
