"use client";

// components/AuthGuard.tsx
//
// ✅ Reads from UserContext — does NOT call useCurrentUser().
// The single useCurrentUser() call lives in authenticated-layout.tsx.

import { useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import { Loader2 } from "lucide-react";
import { useUser } from "@/app/(authenticated)/layout";

interface AuthGuardProps {
  children: React.ReactNode;
}

export default function AuthGuard({ children }: AuthGuardProps) {
  const router      = useRouter();
  const { user, isLoading } = useUser(); // ← context, not useCurrentUser()
  const redirecting = useRef(false);

  useEffect(() => {
    if (isLoading) return;
    if (!user && !redirecting.current) {
      redirecting.current = true;
      router.replace("/signin");
    }
  }, [user, isLoading, router]);

  if (isLoading) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center gap-3">
        <div className="w-9 h-9 rounded-[10px] bg-brand flex items-center justify-center">
          <svg viewBox="0 0 15 15" className="w-4 h-4 fill-white">
            <path d="M7.5 1L2 3.5V8c0 3.3 2.4 5.8 5.5 6.5C10.6 13.8 13 11.3 13 8V3.5L7.5 1z" />
          </svg>
        </div>
        <p className="text-[13px] font-medium text-t3">Checking authentication…</p>
      </div>
    );
  }

  if (!user) return null;

  return <>{children}</>;
}