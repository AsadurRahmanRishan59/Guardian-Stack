// features/admin/user/AdminUserViewContainer.tsx
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
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { UserPlus, Users } from "lucide-react";
import { MasterAdminUserList } from "./MasterAdminUserList";

export function AdminUserViewContainer() {
  const [createModalOpen, setCreateModalOpen] = useState(false);

  const handleCreateNew = () => {
    setCreateModalOpen(true);
  };

  const handleFormSuccess = () => {
    setCreateModalOpen(false);
  };

 return (
    <div className="container mx-auto py-8 space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-xl font-bold flex items-center gap-2">
            <Users className="h-5 w-5" />
            User Management
          </h1>
          <p className="text-muted-foreground mt-1">
            Manage system users, roles, and permissions
          </p>
        </div>
        <Button onClick={handleCreateNew} size="lg">
          <UserPlus className="mr-2 h-5 w-5" />
          Create User
        </Button>
      </div>

      {/* Users Table */}
      <Card>
        <CardHeader>
          <CardTitle>Users List</CardTitle>
        </CardHeader>
        <CardContent>
          <MasterAdminUserList />
        </CardContent>
      </Card>

      {/* Create User Modal */}
      <Dialog open={createModalOpen} onOpenChange={setCreateModalOpen}>
        <DialogContent className="max-w-3xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="text-2xl">Create New User</DialogTitle>
            <DialogDescription>
              Fill in the details to create a new user account
            </DialogDescription>
          </DialogHeader>
          <CreateUserForm onSuccess={handleFormSuccess} />
        </DialogContent>
      </Dialog>
    </div>
  );
}
