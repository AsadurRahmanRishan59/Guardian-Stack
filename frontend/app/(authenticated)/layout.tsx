// app/(authenticated)/layout.tsx
import { AppSidebar } from "@/components/app-sidebar";
import AuthGuard from "@/components/AuthGuard";
import { SiteHeader } from "@/components/site-header";
import { SidebarProvider } from "@/components/ui/sidebar";

export default function AuthenticatedLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <AuthGuard>
      <SidebarProvider className="flex flex-col min-h-screen">
        <div className="antialiased min-h-screen flex flex-col">
          <SiteHeader />
          <div className="flex flex-1">
            <AppSidebar />
            <main className="flex-1 p-4 space-y-4">{children}</main>
          </div>
        </div>
      </SidebarProvider>
    </AuthGuard>
  );
}
