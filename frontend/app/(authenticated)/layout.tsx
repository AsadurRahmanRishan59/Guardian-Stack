"use client";

// app/(authenticated)/layout.tsx
//
// Architecture:
//   useCurrentUser() fires ONCE here.
//   UserContext distributes the result to every child.
//   AuthGuard, AppSidebar, NavUser, all pages — none of them call useCurrentUser().
//
// Why this stops the rate-limiting:
//   Even with staleTime:Infinity, if 4 components call useCurrentUser()
//   before the cache is populated (i.e. on first load), React Query fires
//   the queryFn up to 4 times in the same tick. One context = one call, always.

import React, { createContext, useContext } from "react";
import { useRouter } from "next/navigation";
import { useEffect } from "react";

import { AppSidebar } from "@/components/app-sidebar";
import { SiteHeader } from "@/components/site-header";
import { SidebarProvider } from "@/components/ui/sidebar";
import { useCurrentUser } from "@/features/auth/auth.react.query";
import { UserResponse } from "@/types/auth.types";

// ─── User context ─────────────────────────────────────────────────────────────

interface UserContextValue {
  user: UserResponse | null | undefined;
  isLoading: boolean;
}

const UserContext = createContext<UserContextValue>({
  user:      undefined,
  isLoading: true,
});

/** Use this everywhere instead of useCurrentUser() */
export function useUser(): UserContextValue {
  return useContext(UserContext);
}

// ─── Auth gate (inside the context so it reads from it) ───────────────────────

function AuthGate({ children }: { children: React.ReactNode }) {
  const router            = useRouter();
  const { user, isLoading } = useUser(); // ← context, not a new query

  useEffect(() => {
    if (!isLoading && !user) {
      router.replace("/signin");
    }
  }, [user, isLoading, router]);

  if (isLoading) {
    // Show a minimal warm skeleton while the single query resolves
    return (
      <div className="flex h-svh items-center justify-center bg-surface">
        <div className="flex flex-col items-center gap-3">
          <div className="w-8 h-8 rounded-[8px] bg-brand flex items-center justify-center">
            <svg viewBox="0 0 15 15" className="w-4 h-4 fill-white">
              <path d="M7.5 1L2 3.5V8c0 3.3 2.4 5.8 5.5 6.5C10.6 13.8 13 11.3 13 8V3.5L7.5 1z" />
            </svg>
          </div>
          <div className="text-[13px] text-t3 font-medium">Loading…</div>
        </div>
      </div>
    );
  }

  if (!user) return null; // redirect in flight

  return <>{children}</>;
}

// ─── Layout ───────────────────────────────────────────────────────────────────

export default function AuthenticatedLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  // ✅ THE ONLY useCurrentUser() call in the entire authenticated app shell.
  const { data: user, isLoading } = useCurrentUser();

  return (
    <UserContext.Provider value={{ user: user ?? null, isLoading }}>
      {/*
       * AuthGate is INSIDE the provider so it reads from context.
       * It replaces the old AuthGuard component entirely.
       */}
      <AuthGate>
        <SidebarProvider>
          <div className="flex flex-col min-h-svh w-full bg-surface font-body">
            <SiteHeader />
            <div className="flex flex-1 min-h-0 w-full">
              <AppSidebar />
              <main className="flex-1 min-w-0 overflow-y-auto bg-surface-2">
                <div className="p-6 space-y-6">
                  {children}
                </div>
              </main>
            </div>
          </div>
        </SidebarProvider>
      </AuthGate>
    </UserContext.Provider>
  );
}