"use client";

// components/nav-user.tsx
// ✅ User is passed as a prop from AppSidebar — no API calls here.

import { useState } from "react";
import { ChevronsUpDown, LogOut } from "lucide-react";

import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  useSidebar,
} from "@/components/ui/sidebar";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";

import { UserResponse } from "@/types/auth.types";
import { useLogout } from "@/features/auth/auth.react.query";

export function NavUser({ user }: { user: UserResponse }) {
  const { isMobile }      = useSidebar();
  const logoutMutation    = useLogout();
  const [confirmOpen, setConfirmOpen] = useState(false);

  const initials = user.username?.substring(0, 2).toUpperCase() ?? "U";

  const handleLogout = async () => {
    await logoutMutation.mutateAsync();
    setConfirmOpen(false);
  };

  return (
    <>
      <SidebarMenu>
        <SidebarMenuItem>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <SidebarMenuButton
                size="lg"
                className="
                  rounded-gs transition-colors duration-150
                  hover:bg-surface-2
                  data-[state=open]:bg-brand-soft/50
                  data-[state=open]:text-brand
                "
              >
                <Avatar className="h-8 w-8 rounded-[8px] shrink-0">
                  <AvatarFallback className="rounded-[8px] bg-brand-soft text-brand text-xs font-bold">
                    {initials}
                  </AvatarFallback>
                </Avatar>
                <div className="flex flex-col text-left leading-tight min-w-0">
                  <span className="truncate text-[13px] font-semibold text-t1">{user.username}</span>
                  <span className="truncate text-[11px] text-t4">{user.email}</span>
                </div>
                <ChevronsUpDown className="ml-auto size-3.5 shrink-0 text-t4" />
              </SidebarMenuButton>
            </DropdownMenuTrigger>

            <DropdownMenuContent
              className="
                min-w-56 rounded-gs p-0
                border border-gs-line/50
                bg-surface-card
                shadow-[0_4px_24px_rgba(0,0,0,0.07)]
              "
              side={isMobile ? "bottom" : "right"}
              align="end"
              sideOffset={6}
            >
              {/* User info */}
              <DropdownMenuLabel className="flex items-center gap-3 p-3">
                <Avatar className="h-9 w-9 rounded-[8px] shrink-0">
                  <AvatarFallback className="rounded-[8px] bg-brand-soft text-brand text-sm font-bold">
                    {initials}
                  </AvatarFallback>
                </Avatar>
                <div className="flex flex-col min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-[13px] font-semibold text-t1 truncate">{user.username}</span>
                    <span className={`h-2 w-2 rounded-full shrink-0 ${user.enabled ? "bg-gs-green" : "bg-red-400"}`} />
                  </div>
                  <span className="text-[11px] text-t4 truncate">{user.email}</span>
                </div>
              </DropdownMenuLabel>

              <DropdownMenuSeparator className="bg-gs-line/50" />

              {/* Roles */}
              <DropdownMenuLabel className="px-3 pb-1 text-[9.5px] font-bold uppercase tracking-[0.1em] text-t4">
                Roles
              </DropdownMenuLabel>
              {user.roles.map((role) => (
                <DropdownMenuItem key={role} disabled className="px-3 text-[12px] text-t3 opacity-75 gap-2">
                  <span className="h-1.5 w-1.5 rounded-full bg-brand shrink-0" />
                  {role}
                </DropdownMenuItem>
              ))}

              <DropdownMenuSeparator className="bg-gs-line/50" />

              {/* Logout */}
              <DropdownMenuItem
                onClick={() => setConfirmOpen(true)}
                disabled={logoutMutation.isPending}
                className="
                  px-3 text-[13px] text-red-500 gap-2 cursor-pointer
                  focus:bg-red-50 focus:text-red-600
                  dark:focus:bg-red-950/30 dark:text-red-400
                "
              >
                <LogOut className="h-3.5 w-3.5" />
                Log out
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </SidebarMenuItem>
      </SidebarMenu>

      {/* Confirmation dialog */}
      <Dialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <DialogContent className="max-w-sm rounded-gs border border-gs-line/50 bg-surface-card overflow-hidden shadow-[0_8px_32px_rgba(0,0,0,0.08)]">
          <div className="absolute inset-x-0 top-0 h-[3px] bg-brand" />
          <DialogHeader className="pt-2">
            <DialogTitle className="font-head text-[17px] font-bold tracking-tight text-t1">
              Confirm logout
            </DialogTitle>
          </DialogHeader>
          <p className="text-[13.5px] leading-relaxed text-t3">
            Are you sure you want to log out? You will need to sign in again to access your dashboard.
          </p>
          <DialogFooter className="gap-2">
            <Button
              variant="outline"
              onClick={() => setConfirmOpen(false)}
              className="border-gs-line/80 text-t2 rounded-gs hover:bg-surface-2 hover:text-t1"
            >
              Cancel
            </Button>
            <Button
              onClick={handleLogout}
              disabled={logoutMutation.isPending}
              className="bg-red-500 hover:bg-red-600 text-white rounded-gs border-none"
            >
              {logoutMutation.isPending ? "Logging out…" : "Log out"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}