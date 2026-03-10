// features/auth/auth.react.query.ts
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

// Get current user
export function useCurrentUser() {
    return useQuery({
        queryKey: authKeys.user(),
        queryFn: async () => {
            const response = await getCurrentUser();
            return response.data as UserResponse;
        },

        // ── retry: 0 is critical for public pages ────────────────────────
        //
        // With retry: 1 (old value), a guest visiting the landing page causes:
        //   1. getCurrentUser() → 401 (no session — expected for guests)
        //   2. api.client catches 401 → calls attemptRefresh
        //   3. refresh → 401 (no refresh cookie — expected for guests)
        //   4. React Query retries once more → same chain again
        //
        // retry: 0 means: one attempt, if it fails (401 for guest), treat
        // data as null/undefined and move on. The landing page renders fine.
        // The AuthGate in the authenticated layout handles the actual redirect.
        retry: 0,

        // ── throwOnError: false ───────────────────────────────────────────
        //
        // Without this, a 401 for a guest sets isError=true on the query.
        // Components that check isError show an error UI instead of guest mode.
        // With throwOnError: false, a failed getCurrentUser() gives
        // data: undefined silently — page renders in guest mode as expected.
        throwOnError: false,

        staleTime: Infinity,
        refetchOnMount: false,
        refetchOnWindowFocus: false,
        refetchOnReconnect: false,
    });
}

export function useSignup() {
    const router = useRouter();

    return useMutation({
        mutationFn: async (data: SignupRequest) => await doSignup(data),
        onSuccess: (response) => {
            toast.success(response.message || "Account created! Please verify your email.");
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
                const errorData = error?.data;
                if (errorData === "ACCOUNT_DISABLED") {
                    toast.error("Account not verified. Redirecting...");
                    router.push(`/verify-otp?email=${encodeURIComponent(variables.email)}`);
                    return;
                }
                toast.error(error.message || 'Failed to login');
            } else {
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
            router.push('/signin');
        },
    });
}

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