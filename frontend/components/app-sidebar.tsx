"use client";

// components/app-sidebar.tsx
// ✅ NO useCurrentUser() — reads from UserContext via useUser()

import * as React from "react";
import Image from "next/image";
import { useRouter } from "next/navigation";

import { NavMain } from "@/components/nav-main";
import { NavUser } from "@/components/nav-user";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from "@/components/ui/sidebar";

import { navigationConfig } from "@/lib/navigation-config";
import { filterNavigationByRole } from "@/lib/utils/role-check";
import { useUser } from "@/app/(authenticated)/layout";

export function AppSidebar({ ...props }: React.ComponentProps<typeof Sidebar>) {
  const router              = useRouter();
  const { user, isLoading } = useUser(); // ← context, not a query

  const filteredNavigation = React.useMemo(() => {
    if (!user?.roles) return [];
    return filterNavigationByRole(navigationConfig, user.roles);
  }, [user]);

  const handleHomeClick = React.useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    router.push("/");
  }, [router]);

  const sidebarCls =
    "top-(--header-height) h-[calc(100svh-var(--header-height))]! flex flex-col border-r border-gs-line/50";

  return (
    <Sidebar className={sidebarCls} {...props}>

      {/* Header */}
      <SidebarHeader className="shrink-0 border-b border-gs-line/50 px-3 py-2">
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton
              size="lg"
              onClick={handleHomeClick}
              className="rounded-gs hover:bg-brand-soft/60 active:bg-brand-soft transition-colors duration-200"
            >
              <Image
                src="/images/GS.png"
                alt="Guardian Stack"
                width={32} height={32}
                className="rounded-md shrink-0"
                priority
              />
              <div className="grid flex-1 text-left text-sm leading-tight">
                <span className="truncate font-semibold text-t1">Guardian Stack</span>
                <span className="truncate text-[11px] text-t4">Admin Portal</span>
              </div>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>

      {/* Nav content — loading skeleton or real items */}
      <SidebarContent className="flex-1 min-h-0 overflow-y-auto px-2 py-2">
        {isLoading || !user ? (
          <div className="flex flex-col gap-2 px-1 py-2">
            {[1, 2, 3].map((i) => (
              <div key={i} className="h-8 rounded-gs bg-surface-2 animate-pulse" />
            ))}
          </div>
        ) : (
          filteredNavigation.map((section) => (
            <NavMain
              key={section.parentName}
              items={section.navMain}
              parentName={section.parentName}
            />
          ))
        )}
      </SidebarContent>

      {/* Footer user menu */}
      {user && (
        <SidebarFooter className="shrink-0 border-t border-gs-line/50 px-2 py-2">
          <NavUser
            user={{
              userId:   user.userId,
              username: user.username,
              email:    user.email,
              enabled:  user.enabled,
              roles:    user.roles,
            }}
          />
        </SidebarFooter>
      )}

    </Sidebar>
  );
}