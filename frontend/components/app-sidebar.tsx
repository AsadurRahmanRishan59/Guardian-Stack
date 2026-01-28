// components/app-sidebar.tsx (Updated)
"use client";
import * as React from "react";
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
import Image from "next/image";
import { useRouter } from "next/navigation";
import { navigationConfig } from "@/lib/navigation-config";
import { filterNavigationByRole } from "@/lib/utils/role-check";
import { useCurrentUser } from "@/features/auth/auth.react.query";

export function AppSidebar({ ...props }: React.ComponentProps<typeof Sidebar>) {
  const router = useRouter();
  const { data: user, isLoading } = useCurrentUser();

  // Filter navigation based on user roles
  const filteredNavigation = React.useMemo(() => {
    if (!user || !user.roles) {
      return [];
    }
    return filterNavigationByRole(navigationConfig, user.roles);
  }, [user]);

  const handleHomeClick = React.useCallback(
    (e: React.MouseEvent) => {
      e.preventDefault();
      router.push("/");
    },
    [router]
  );

  // Show loading state or nothing while user data is loading
  if (isLoading || !user) {
    return (
      <Sidebar
        className="top-(--header-height) h-[calc(100svh-var(--header-height))]!"
        {...props}
      >
        <SidebarHeader>
          <SidebarMenu>
            <SidebarMenuItem>
              <SidebarMenuButton size="lg" onClick={handleHomeClick}>
                <Image
                  src="/images/GS.png"
                  alt="Guardian Stack Logo"
                  width={32}
                  height={32}
                  className="rounded-md"
                  priority
                />
                <div className="grid flex-1 text-left text-sm leading-tight">
                  <span className="truncate font-medium">Voucher Management</span>
                </div>
              </SidebarMenuButton>
            </SidebarMenuItem>
          </SidebarMenu>
        </SidebarHeader>
        <SidebarContent>
          <div className="p-4 text-sm text-muted-foreground">Loading...</div>
        </SidebarContent>
      </Sidebar>
    );
  }

  return (
    <Sidebar
      className="top-(--header-height) h-[calc(100svh-var(--header-height))]!"
      {...props}
    >
      <SidebarHeader>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton size="lg" onClick={handleHomeClick}>
              <Image
                src="/images/GS.png"
                alt="Guardian Stack Logo"
                width={32}
                height={32}
                className="rounded-md"
                priority
              />
              <div className="grid flex-1 text-left text-sm leading-tight">
                <span className="truncate font-medium">Guardian Stack</span>
              </div>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>
      <SidebarContent>
        {filteredNavigation.map((section) => (
          <NavMain
            key={section.parentName}
            items={section.navMain}
            parentName={section.parentName}
          />
        ))}
      </SidebarContent>
      <SidebarFooter>
        <NavUser
          user={{
            userId: user.userId,
            username: user.username,
            email: user.email,
            enabled: user.enabled,
            roles: user.roles,
          }}
        />
      </SidebarFooter>
    </Sidebar>
  );
}