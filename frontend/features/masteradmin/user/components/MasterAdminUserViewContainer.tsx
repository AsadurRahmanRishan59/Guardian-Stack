// features/admin/user/components/AdminUserViewContainer.tsx
"use client";

import { useState } from "react";
import { CreateUserForm } from "./CreateUserForm";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { UserPlus, Users } from "lucide-react";
import { MasterAdminUserList } from "./MasterAdminUserList";

export function AdminUserViewContainer() {
  const [createModalOpen, setCreateModalOpen] = useState(false);

  return (
    <div className="space-y-3">
      {/* ── Page header ── */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-lg sm:text-xl font-bold font-head text-t1 flex items-center gap-2">
            <span className="flex items-center justify-center w-8 h-8 rounded-gs bg-brand-soft">
              <Users className="h-4 w-4 text-brand" />
            </span>
            User Management
          </h1>
          <p className="text-sm text-t3 mt-1 ml-10">
            Manage system users, roles, and permissions
          </p>
        </div>

        <Button
          onClick={() => setCreateModalOpen(true)}
          className="bg-brand hover:bg-brand-hover text-white gap-2 self-start sm:self-auto"
        >
          <UserPlus className="h-4 w-4" />
          Create User
        </Button>
      </div>

      {/* ── Table ── */}
      <MasterAdminUserList />

      {/* ── Create modal ── */}
      <Dialog open={createModalOpen} onOpenChange={setCreateModalOpen}>
        <DialogContent className="max-w-3xl max-h-[90vh] overflow-y-auto border-gs-line bg-surface-card">
          <DialogHeader>
            <DialogTitle className="text-xl font-head text-t1">
              Create New User
            </DialogTitle>
            <DialogDescription className="text-t3">
              Fill in the details to create a new user account.
            </DialogDescription>
          </DialogHeader>
          <CreateUserForm onSuccess={() => setCreateModalOpen(false)} />
        </DialogContent>
      </Dialog>
    </div>
  );
}