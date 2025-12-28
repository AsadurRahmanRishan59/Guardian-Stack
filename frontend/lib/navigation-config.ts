// lib/navigation-config.ts
import { AppRole } from "@/types/auth.types";
import {  FileClock, LucideIcon, ShieldUser } from "lucide-react";


export interface NavItem {
  title: string;
  url: string;
  icon: LucideIcon;
  isActive?: boolean;
  items?: {
    title: string;
    url: string;
  }[];
  roles: AppRole[]; // Required roles to see this item
}

export interface NavigationSection {
  parentName: string;
  navMain: NavItem[];
  roles: AppRole[]; // Required roles to see this section
}

export const navigationConfig: NavigationSection[] = [
  {
    parentName: "Admin",
    roles: [AppRole.MASTER_ADMIN, AppRole.ADMIN], // Only admins can see this section
    navMain: [
      {
        title: "User",
        url: "/admin/user",
        icon: ShieldUser,
        isActive: true,
        roles: [AppRole.MASTER_ADMIN, AppRole.ADMIN],
        items: [
          {
            title: "Setup",
            url: "/admin/user/setup",
          },
          {
            title: "List",
            url: "/admin/user/list",
          },
        ],
      },
      {
        title: "Audit",
        url: "/admin/audit",
        icon: FileClock,
        isActive: true,
        roles: [AppRole.MASTER_ADMIN, AppRole.ADMIN],
        items: [
          {
            title: "User Log",
            url: "/admin/audit/user-log",
          },
          {
            title: "Login Log",
            url: "/admin/audit/login-log",
          },
        ],
      },
    ],
  },
  // {
  //   parentName: "Vouchers",
  //   roles: [AppRole.ADMIN, AppRole.ACCOUNT_MANAGER, AppRole.ACCOUNT_USER],
  //   navMain: [
  //     {
  //       title: "Accounts",
  //       url: "/accounts",
  //       icon: Calculator,
  //       isActive: true,
  //       roles: [AppRole.ADMIN, AppRole.ACCOUNT_MANAGER, AppRole.ACCOUNT_USER],
  //       items: [
  //         {
  //           title: "Upload",
  //           url: "/accounts/upload",
  //         },
  //         {
  //           title: "List",
  //           url: "/accounts/list",
  //         },
  //       ],
  //     },
  //   ],
  // },
];