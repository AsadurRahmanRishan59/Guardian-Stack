// app/admin/layout.tsx

import { RoleGuard } from "@/components/RoleGuard";
import { AppRole } from "@/types/auth.types";
import { ReactNode } from "react";

export default async function AdminLayout({
  children,
}: {
  children: ReactNode;
}) {
  return (
    <RoleGuard requiredRoles={[AppRole.MASTER_ADMIN,AppRole.ADMIN]}>
      <>{children}</>
    </RoleGuard>
  );
}
