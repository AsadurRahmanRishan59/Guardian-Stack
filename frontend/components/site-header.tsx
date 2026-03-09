"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { SidebarIcon } from "lucide-react";

import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { useSidebar } from "@/components/ui/sidebar";
import { ThemeToggle } from "@/components/theme-toggle";

// ─── Segment → human label ────────────────────────────────────────────────────
const ROUTE_LABELS: Record<string, string> = {
  admin:          "Admin",
  "master-data":  "Master Data",
  tariffs:        "Tariffs",
  motor:          "Motor",
  "rate-table":   "Rate Table",
  "policy-terms": "Policy Terms",
  config:         "Configuration",
  overseas:       "Overseas Medical",
  health:         "Health",
  home:           "Home",
  life:           "Term Life",
  sme:            "SME Business",
  user:           "User",
  setup:          "Setup",
  list:           "List",
  audit:          "Audit",
  "user-log":     "User Log",
  "login-log":    "Login Log",
};

function toLabel(segment: string) {
  return (
    ROUTE_LABELS[segment] ??
    segment.replace(/-/g, " ").replace(/\b\w/g, (c) => c.toUpperCase())
  );
}

interface Crumb { label: string; href: string; isLast: boolean }

function buildCrumbs(pathname: string): Crumb[] {
  const parts = pathname.replace(/^\//, "").split("/").filter(Boolean);
  return parts.map((seg, i) => ({
    label:  toLabel(seg),
    href:   "/" + parts.slice(0, i + 1).join("/"),
    isLast: i === parts.length - 1,
  }));
}

// ─── Component ────────────────────────────────────────────────────────────────

export function SiteHeader() {
  const { toggleSidebar } = useSidebar();
  const pathname = usePathname();
  const crumbs   = buildCrumbs(pathname);

  return (
    <header
      className="
        sticky top-0 z-50
        flex w-full items-center
        h-[var(--header-height,52px)]
        border-b border-gs-line/50
        bg-surface-card/95 backdrop-blur-sm
      "
    >
      <div className="flex w-full items-center gap-2 px-3">

        {/* Sidebar toggle */}
        <Button
          variant="ghost"
          size="icon"
          onClick={toggleSidebar}
          className="
            h-8 w-8 shrink-0 rounded-gs
            text-t3 hover:text-t1 hover:bg-surface-2
            transition-colors duration-150
          "
        >
          <SidebarIcon className="size-4" />
          <span className="sr-only">Toggle sidebar</span>
        </Button>

        <Separator orientation="vertical" className="h-4 bg-gs-line/60" />

        {/* Breadcrumbs */}
        {crumbs.length > 0 && (
          <Breadcrumb className="hidden sm:block">
            <BreadcrumbList className="flex items-center gap-1">
              {crumbs.map((crumb, i) => (
                <span key={crumb.href} className="flex items-center gap-1">
                  {i > 0 && (
                    <BreadcrumbSeparator className="text-t4 mx-0.5" />
                  )}
                  <BreadcrumbItem>
                    {crumb.isLast ? (
                      <BreadcrumbPage className="text-[13px] font-semibold text-t1">
                        {crumb.label}
                      </BreadcrumbPage>
                    ) : (
                      <BreadcrumbLink asChild>
                        <Link
                          href={crumb.href}
                          className="text-[13px] text-t3 transition-colors hover:text-brand"
                        >
                          {crumb.label}
                        </Link>
                      </BreadcrumbLink>
                    )}
                  </BreadcrumbItem>
                </span>
              ))}
            </BreadcrumbList>
          </Breadcrumb>
        )}

        {/* Right side */}
        <div className="ml-auto flex items-center gap-2">
          <ThemeToggle />
        </div>

      </div>
    </header>
  );
}