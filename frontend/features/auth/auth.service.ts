import { api } from "@/lib/api.client";
import { ApiResponse } from "@/types/api.types";
import { LoginCredentials, LoginResponseDTO, SignupRequest, UserResponse, VerifyOTPData } from "@/types/auth.types";

export function doSignup(signupRequest: SignupRequest): Promise<ApiResponse<LoginResponseDTO>> {
    return api.client.post('/auth/signup', signupRequest);
}

export function doVerifyOTP(data: VerifyOTPData): Promise<ApiResponse<LoginResponseDTO>> {
    return api.client.post('/auth/verify-otp', data);
}

export function doResendOTP(email: string): Promise<ApiResponse<string>> {
    return api.client.post('/auth/resend-otp', {email});
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

