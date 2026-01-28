"use client";

import { useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import { Loader2 } from "lucide-react";
import { useCurrentUser } from "@/features/auth/auth.react.query";

interface AuthGuardProps {
  children: React.ReactNode;
}

export default function AuthGuard({ children }: AuthGuardProps) {
  const router = useRouter();
  const { data: user, isLoading, isError, error } = useCurrentUser();

  // Prevent multiple redirects on re-renders
  const redirecting = useRef(false);

  useEffect(() => {
    if (isLoading) return;

    // If error OR no user → redirect
    if (!user || isError) {
      if (!redirecting.current) {
        redirecting.current = true;
        console.warn("🔒 AuthGuard: Not authenticated → redirect to /signin");
        router.replace("/signin");
      }
    }
  }, [user, isLoading, isError, router]);

  // Loading placeholder (better looking)
  if (isLoading) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center text-center">
        <Loader2 className="w-10 h-10 animate-spin text-muted-foreground mb-3" />
        <p className="text-sm text-muted-foreground">Checking authentication…</p>
      </div>
    );
  }

  // Show error (session expired, token invalid, backend unreachable)
  if (isError) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center text-center p-6">
        <p className="text-red-600 dark:text-red-400 font-semibold mb-2">
          Authentication Error
        </p>
        <p className="text-muted-foreground mb-4">
          {(error as Error)?.message ??
            "Failed to verify session. Please login again."}
        </p>
        <button
          onClick={() => router.replace("/signin")}
          className="px-4 py-2 bg-primary text-primary-foreground rounded-md"
        >
          Go to Login
        </button>
      </div>
    );
  }

  // While redirecting, show nothing
  if (!user) return null;

  // Authenticated → render content
  return <>{children}</>;
}
