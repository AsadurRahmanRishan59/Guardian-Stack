// lib/navigation-config.ts
import { AppRole } from "@/types/auth.types";
import type { LucideIcon } from "lucide-react";
import {
  Database, FileClock, ShieldUser,
  Car, Globe, HeartPulse, Home, Shield, Briefcase,
  Receipt,
  FileText, Settings2, BarChart3,
  UserPlus, Users,
  ScrollText, LogIn,
} from "lucide-react";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface NavItem {
  title: string;
  url: string;
  icon: LucideIcon;
  isActive?: boolean;
  roles: AppRole[];
  items?: NavItem[];
}

export interface NavigationSection {
  parentName: string;
  roles: AppRole[];
  navMain: NavItem[];
}

// ─── Config ───────────────────────────────────────────────────────────────────

export const navigationConfig: NavigationSection[] = [
  
  // ── Dashboard Section (Top Level) ───────────────────────────────────
  {
    parentName: "Dashboard",
    roles: [AppRole.MASTER_ADMIN, AppRole.ADMIN, AppRole.USER],
    navMain: [
      {
        title: "Dashboard",
        url: "/dashboard",
        icon: BarChart3,
        roles: [AppRole.MASTER_ADMIN, AppRole.ADMIN, AppRole.USER],
      },
    ],
  },

  // ── Admin Section ───────────────────────────────────────────────────
  {
    parentName: "Admin",
    roles: [AppRole.MASTER_ADMIN, AppRole.ADMIN],
    navMain: [

      // ── Master Data ──────────────────────────────────────────────────────
      {
        title: "Master Data",
        url: "/admin/master-data",
        icon: Database,
        isActive: true,
        roles: [AppRole.MASTER_ADMIN, AppRole.ADMIN],
        items: [
          {
            title: "Tariffs",
            url: "/admin/master-data/tariffs",
            icon: Receipt,
            roles: [AppRole.MASTER_ADMIN, AppRole.ADMIN],
            items: [
              {
                title: "Motor",
                url: "/admin/master-data/tariffs/motor",
                icon: Car,
                roles: [AppRole.MASTER_ADMIN, AppRole.ADMIN],
                items: [
                  { title: "Rate Table",   url: "/admin/master-data/tariffs/motor/rate-table",    icon: BarChart3, roles: [AppRole.MASTER_ADMIN, AppRole.ADMIN] },
                  { title: "Policy Terms", url: "/admin/master-data/tariffs/motor/policy-terms",  icon: FileText,  roles: [AppRole.MASTER_ADMIN, AppRole.ADMIN] },
                  { title: "Configuration",url: "/admin/master-data/tariffs/motor/config",         icon: Settings2, roles: [AppRole.MASTER_ADMIN, AppRole.ADMIN] },
                ],
              },
              {
                title: "Overseas Medical",
                url: "/admin/master-data/tariffs/overseas",
                icon: Globe,
                roles: [AppRole.MASTER_ADMIN, AppRole.ADMIN],
                items: [
                  { title: "Rate Table",   url: "/admin/master-data/tariffs/overseas/rate-table",   icon: BarChart3, roles: [AppRole.MASTER_ADMIN, AppRole.ADMIN] },
                  { title: "Policy Terms", url: "/admin/master-data/tariffs/overseas/policy-terms", icon: FileText,  roles: [AppRole.MASTER_ADMIN, AppRole.ADMIN] },
                ],
              },
              {
                title: "Health",
                url: "/admin/master-data/tariffs/health",
                icon: HeartPulse,
                roles: [AppRole.MASTER_ADMIN, AppRole.ADMIN],
                items: [
                  { title: "Rate Table",   url: "/admin/master-data/tariffs/health/rate-table",   icon: BarChart3, roles: [AppRole.MASTER_ADMIN, AppRole.ADMIN] },
                  { title: "Policy Terms", url: "/admin/master-data/tariffs/health/policy-terms", icon: FileText,  roles: [AppRole.MASTER_ADMIN, AppRole.ADMIN] },
                ],
              },
              {
                title: "Home",
                url: "/admin/master-data/tariffs/home",
                icon: Home,
                roles: [AppRole.MASTER_ADMIN, AppRole.ADMIN],
                items: [
                  { title: "Rate Table",   url: "/admin/master-data/tariffs/home/rate-table",   icon: BarChart3, roles: [AppRole.MASTER_ADMIN, AppRole.ADMIN] },
                  { title: "Policy Terms", url: "/admin/master-data/tariffs/home/policy-terms", icon: FileText,  roles: [AppRole.MASTER_ADMIN, AppRole.ADMIN] },
                ],
              },
              {
                title: "Term Life",
                url: "/admin/master-data/tariffs/life",
                icon: Shield,
                roles: [AppRole.MASTER_ADMIN, AppRole.ADMIN],
                items: [
                  { title: "Rate Table",   url: "/admin/master-data/tariffs/life/rate-table",   icon: BarChart3, roles: [AppRole.MASTER_ADMIN, AppRole.ADMIN] },
                  { title: "Policy Terms", url: "/admin/master-data/tariffs/life/policy-terms", icon: FileText,  roles: [AppRole.MASTER_ADMIN, AppRole.ADMIN] },
                ],
              },
              {
                title: "SME Business",
                url: "/admin/master-data/tariffs/sme",
                icon: Briefcase,
                roles: [AppRole.MASTER_ADMIN, AppRole.ADMIN],
                items: [
                  { title: "Rate Table",   url: "/admin/master-data/tariffs/sme/rate-table",   icon: BarChart3, roles: [AppRole.MASTER_ADMIN, AppRole.ADMIN] },
                  { title: "Policy Terms", url: "/admin/master-data/tariffs/sme/policy-terms", icon: FileText,  roles: [AppRole.MASTER_ADMIN, AppRole.ADMIN] },
                ],
              },
            ],
          },
        ],
      },

      // ── User ─────────────────────────────────────────────────────────────
      {
        title: "User",
        url: "/admin/user",
        icon: ShieldUser,
        isActive: true,
        roles: [AppRole.MASTER_ADMIN, AppRole.ADMIN],
        items: [
          { title: "User Management", url: "/admin/user/user-management", icon: UserPlus, roles: [AppRole.MASTER_ADMIN, AppRole.ADMIN] },
        ],
      },

      // ── Audit ─────────────────────────────────────────────────────────────
      {
        title: "Audit",
        url: "/admin/audit",
        icon: FileClock,
        isActive: true,
        roles: [AppRole.MASTER_ADMIN, AppRole.ADMIN],
        items: [
          { title: "User Log",          url: "/admin/audit/user-log",                icon: ScrollText, roles: [AppRole.MASTER_ADMIN, AppRole.ADMIN] },
          { title: "Security Log",         url: "/admin/audit/security-log",               icon: LogIn,      roles: [AppRole.MASTER_ADMIN, AppRole.ADMIN] },
          {
            title: "Tariff",
            url: "/admin/audit/tariff",
            icon: Receipt,
            roles: [AppRole.MASTER_ADMIN],
            items: [
              { title: "Motor Log", url: "/admin/audit/tariff/motor-log", icon: Car, roles: [AppRole.MASTER_ADMIN] },
            ],
          },
        ],
      },
    ],
  },
];