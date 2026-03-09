"use client";

/**
 * components/nav-main.tsx
 *
 * Recursive sidebar nav — unlimited depth.
 * · Smooth open/close animation via data-[state=open/closed] on CollapsibleContent
 * · Soft warm borders, never harsh black
 * · Active highlight propagates up to all ancestors
 * · Auto-expands ancestor branches on page load
 */

import * as React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { ChevronRight } from "lucide-react";
import { cn } from "@/lib/utils";

import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import {
  SidebarGroup,
  SidebarGroupLabel,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarMenuSub,
  SidebarMenuSubButton,
  SidebarMenuSubItem,
} from "@/components/ui/sidebar";

import type { NavItem } from "@/lib/navigation-config";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function matchPath(pathname: string, url: string): boolean {
  if (url === "/") return pathname === "/";
  return pathname === url || pathname.startsWith(url + "/");
}

function hasActiveDescendant(pathname: string, item: NavItem): boolean {
  if (matchPath(pathname, item.url)) return true;
  return item.items?.some((c) => hasActiveDescendant(pathname, c)) ?? false;
}

// ─── Animated collapsible wrapper ────────────────────────────────────────────
/*
 * shadcn's CollapsibleContent sets data-[state=open] / data-[state=closed].
 * We use those attributes to drive a CSS height + opacity transition.
 * This is added to globals.css via @layer utilities below — but we also
 * inline the animation classes here so no extra global CSS is needed.
 */
function AnimatedCollapsibleContent({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <CollapsibleContent
      className={cn(
        /*
         * Tailwind v4 / shadcn: CollapsibleContent already sets
         * data-[state=closed]:hidden by default in some versions.
         * We override with overflow-hidden + grid rows trick for smooth height.
         *
         * The grid-rows animation is the most reliable cross-browser way
         * to animate height from 0 to auto without JS measurement.
         */
        "overflow-hidden",
        "data-[state=open]:animate-collapsible-down",
        "data-[state=closed]:animate-collapsible-up",
        className
      )}
    >
      {children}
    </CollapsibleContent>
  );
}

// ─── Recursive node ───────────────────────────────────────────────────────────

function NavNode({ item, depth }: { item: NavItem; depth: number }) {
  const pathname   = usePathname();
  const isExact    = matchPath(pathname, item.url);
  const isAncestor = !isExact && hasActiveDescendant(pathname, item);
  const isHighlit  = isExact || isAncestor;
  const hasKids    = !!item.items?.length;

  // ── Leaf — depth 0 ────────────────────────────────────────────────────────
  if (!hasKids && depth === 0) {
    return (
      <SidebarMenuItem>
        <SidebarMenuButton asChild isActive={isExact}>
          <Link
            href={item.url}
            className={cn(
              "flex items-center gap-2.5 rounded-gs text-[13.5px] font-medium",
              "transition-colors duration-150",
              isExact
                ? "bg-brand-soft text-brand font-semibold"
                : "text-t2 hover:bg-surface-2 hover:text-t1"
            )}
          >
            <item.icon className={cn("size-4 shrink-0", isExact ? "text-brand" : "text-t3")} />
            <span className="flex-1 truncate">{item.title}</span>
            {isExact && <span className="ml-auto h-1.5 w-1.5 shrink-0 rounded-full bg-brand" />}
          </Link>
        </SidebarMenuButton>
      </SidebarMenuItem>
    );
  }

  // ── Leaf — depth > 0 ──────────────────────────────────────────────────────
  if (!hasKids) {
    return (
      <SidebarMenuSubItem>
        <SidebarMenuSubButton asChild isActive={isExact}>
          <Link
            href={item.url}
            className={cn(
              "flex items-center gap-2 rounded-gs-sm text-[12.5px] font-medium h-8",
              "transition-colors duration-150",
              isExact
                ? "bg-brand-soft text-brand font-semibold"
                : "text-t3 hover:bg-surface-2 hover:text-t1"
            )}
          >
            <item.icon
              className={cn(
                "shrink-0",
                depth === 1 ? "size-[13px]" : "size-[11px]",
                isExact ? "text-brand" : "text-t4"
              )}
            />
            <span className="flex-1 truncate">{item.title}</span>
            {isExact && <span className="ml-auto h-1.5 w-1.5 shrink-0 rounded-full bg-brand" />}
          </Link>
        </SidebarMenuSubButton>
      </SidebarMenuSubItem>
    );
  }

  // ── Branch — depth 0 ──────────────────────────────────────────────────────
  if (depth === 0) {
    return (
      <Collapsible defaultOpen={isHighlit} className="group/col">
        <SidebarMenuItem>
          <CollapsibleTrigger asChild>
            <SidebarMenuButton
              tooltip={item.title}
              isActive={isHighlit}
              className={cn(
                "flex items-center gap-2.5 rounded-gs text-[13.5px] font-medium w-full",
                "transition-colors duration-150",
                isHighlit
                  ? "bg-brand-soft/50 text-t1"
                  : "text-t2 hover:bg-surface-2 hover:text-t1"
              )}
            >
              <item.icon
                className={cn(
                  "size-4 shrink-0 transition-colors",
                  isHighlit ? "text-brand" : "text-t3"
                )}
              />
              <span className="flex-1 truncate">{item.title}</span>
              <ChevronRight
                className={cn(
                  "ml-auto size-3.5 shrink-0 text-t4",
                  "transition-transform duration-200 ease-in-out",
                  "group-data-[state=open]/col:rotate-90"
                )}
              />
            </SidebarMenuButton>
          </CollapsibleTrigger>

          <AnimatedCollapsibleContent>
            <SidebarMenuSub
              className={cn(
                "ml-4 border-l",
                isHighlit ? "border-brand/25" : "border-gs-line/40"
              )}
            >
              {item.items!.map((child) => (
                <NavNode key={child.url} item={child} depth={depth + 1} />
              ))}
            </SidebarMenuSub>
          </AnimatedCollapsibleContent>
        </SidebarMenuItem>
      </Collapsible>
    );
  }

  // ── Branch — depth ≥ 1 ────────────────────────────────────────────────────
  return (
    <Collapsible defaultOpen={isHighlit} className="group/sub">
      <SidebarMenuSubItem>
        <CollapsibleTrigger asChild>
          <SidebarMenuSubButton
            isActive={isHighlit}
            className={cn(
              "flex w-full items-center gap-2 rounded-gs-sm text-[12.5px] font-medium h-8",
              "transition-colors duration-150",
              isHighlit
                ? "bg-brand-soft/50 text-t1"
                : "text-t3 hover:bg-surface-2 hover:text-t1"
            )}
          >
            <item.icon
              className={cn(
                "shrink-0 transition-colors",
                depth === 1 ? "size-[13px]" : "size-[11px]",
                isHighlit ? "text-brand" : "text-t4"
              )}
            />
            <span className="flex-1 truncate">{item.title}</span>
            <ChevronRight
              className={cn(
                "ml-auto size-3 shrink-0 text-t4",
                "transition-transform duration-200 ease-in-out",
                "group-data-[state=open]/sub:rotate-90"
              )}
            />
          </SidebarMenuSubButton>
        </CollapsibleTrigger>

        <AnimatedCollapsibleContent>
          <SidebarMenuSub
            className={cn(
              "ml-3 border-l",
              isHighlit ? "border-brand/25" : "border-gs-line/40"
            )}
          >
            {item.items!.map((child) => (
              <NavNode key={child.url} item={child} depth={depth + 1} />
            ))}
          </SidebarMenuSub>
        </AnimatedCollapsibleContent>
      </SidebarMenuSubItem>
    </Collapsible>
  );
}

// ─── Public export ────────────────────────────────────────────────────────────

export function NavMain({
  items,
  parentName,
}: {
  items: NavItem[];
  parentName: string;
}) {
  return (
    <SidebarGroup className="px-0 py-1">
      <SidebarGroupLabel className="px-3 mb-0.5 text-[10px] font-bold tracking-[0.12em] uppercase text-t4">
        {parentName}
      </SidebarGroupLabel>
      <SidebarMenu>
        {items.map((item) => (
          <NavNode key={item.url} item={item} depth={0} />
        ))}
      </SidebarMenu>
    </SidebarGroup>
  );
}