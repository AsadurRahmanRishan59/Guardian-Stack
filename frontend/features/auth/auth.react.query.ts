import { LoginCredentials, PasswordResetRequest, SignupRequest, UserResponse, VerifyOTPData } from "@/types/auth.types";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { doSignin, doResendOTP, doSignup, doVerifyOTP, getCurrentUser, logout, doForgotPassword, doResetPassword } from "./auth.service";
import { toast } from "sonner";
import { isServerError } from "@/lib/api/error-handling";

// Query keys
export const authKeys = {
    all: ['auth'] as const,
    check: () => [...authKeys.all, 'check'] as const,
    user: () => [...authKeys.all, 'user'] as const,
};

//Get current user
export function useCurrentUser() {
    return useQuery({
        queryKey: authKeys.user(),
        queryFn: async () => {
            const response = await getCurrentUser();
            return response.data as UserResponse;
        },
        retry: 1,
        refetchOnMount: false,
        refetchOnWindowFocus: false,
        refetchOnReconnect: false,
        staleTime: Infinity

    });
}

export function useSignup() {
    const router = useRouter();

    return useMutation({
        mutationFn: async (data: SignupRequest) => await doSignup(data),
        onSuccess: (response) => {
            // GuardianStack Flow: 
            // Signup is successful, but user is NOT enabled yet.
            // We redirect them to the OTP verification page.
            toast.success(response.message || "Account created! Please verify your email.");

            // Pass the email to the verify page via query params so the user doesn't have to re-type it
            const email = response.data?.userResponse.email;
            router.push(`/verify-otp?email=${encodeURIComponent(email || "")}`);
        },
        onError: (error) => {
            toast.error(error.message || "Registration failed");
        }
    });
}

// Login mutation
export function useSignin() {
    const queryClient = useQueryClient();
    const router = useRouter();

    return useMutation({
        mutationFn: async (credentials: LoginCredentials) => await doSignin(credentials),
        onSuccess: async (response) => {
            if (response.data?.userResponse) {
                queryClient.setQueryData(authKeys.user(), response.data.userResponse);
            }
            toast.success(response?.message || "Login successful");
            router.push('/dashboard');
        },
        onError: (error: unknown, variables) => {
            if (isServerError(error)) {
                // Based on Spring Boot Record: data contains "ACCOUNT_DISABLED"
                const errorData = error?.data;

                if (errorData === "ACCOUNT_DISABLED") {
                    toast.error("Account not verified. Redirecting...");
                    router.push(`/verify-otp?email=${encodeURIComponent(variables.email)}`);
                    return;
                }

                // Handle other specific server errors (Bad Credentials, etc.)
                toast.error(error.message || 'Failed to login');
            } else {
                // This handles network errors or unexpected JS crashes
                toast.error('A network error occurred. Please try again.');
            }
        }
    });
}

// Logout mutation
export function useLogout() {
    const queryClient = useQueryClient();
    const router = useRouter();

    return useMutation({
        mutationFn: async () => await logout(),
        onSuccess: () => {
            queryClient.clear();
            router.push('/login');
        },
    });
}


// features/auth/auth.react.query.ts

export function useVerifyOtp() {
    return useMutation({
        mutationFn: async (data: VerifyOTPData) => {
            const response = await doVerifyOTP(data);
            return response.data;
        },
        onSuccess: () => {
            toast.success("Email verified successfully! You can now login.");
        },
        onError: (error) => {
            toast.error(error.message || 'Failed to Verify OTP');
        }
    });
}

export function useResendOtp() {
    return useMutation({
        mutationFn: async ({ email }: { email: string }) => {
            const response = await doResendOTP(email);
            return response.data;
        },
        onSuccess: () => {
            toast.success("A new code has been sent to your email.");
        },
        onError: (error) => {
            toast.error(error.message || "Failed to resend code.");
        }
    });
}

export function useForgotPassword() {
    const router = useRouter();
    return useMutation({
        mutationFn: async ({ email }: { email: string }) => {
            const response = await doForgotPassword(email);
            return response;
        },
        onSuccess: (response, variables) => {
            toast.success(response.message || "A new code has been sent to your email.");
            // Push them to the reset password page
            router.push(`/reset-password?email=${encodeURIComponent(variables.email)}`);
        },
        onError: (error) => {
            toast.error(error.message || "Failed to resend code.");
        }
    });
}

export function useResetPassword() {
    const router = useRouter();

    return useMutation({
        mutationFn: async (data: PasswordResetRequest) => await doResetPassword(data),
        onSuccess: (response) => {

            toast.success(response.message || "Password has been reset successfully.");
            router.push(`/signin`);
        },
        onError: (error) => {
            toast.error(error.message || "Password Reset failed");
        }
    });
}