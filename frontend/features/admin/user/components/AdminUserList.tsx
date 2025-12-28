//features/admin/user/components/AdminUserList.tsx
"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { ColumnDef } from "@tanstack/react-table";
import { Loader2 } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

// Import reusable components
import { useDataTable, TableColumnConfig } from "@/lib/hooks/useDataTable";
import { TableControls } from "@/components/table/TableControls";
import { DataTable } from "@/components/table/DataTable";
import {
  createActionsColumn,
  createIndexColumn,
  createIsActiveColumn,
  generateColumns,
} from "@/lib/generateColumns";

import {
  AdminUserView,
  AdminUserViewFilterOptions,
  AdminUserViewSearchCriteria,
} from "../user.types";
import {
  useQueryAdminUserView,
  useQueryAdminUserViewFilterOptions,
} from "../user.react.query";
import { AdminUserViewFilterFormData } from "../user.schema";
import { AdminUserViewFilterForm } from "./AdminUserViewFilterForm";
import AdminUserModal from "./AdminUserModal";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { CreateUserForm } from "./CreateUserForm";

interface AdminUserListRow {
  userId: number;
  username: string;
  email: string;
  signUpMethod: string;
  isTwoFactorEnabled: boolean;
  roles: string;
  enabled: boolean;
  createdDate: string;
}

const COLUMN_CONFIGS: TableColumnConfig<AdminUserListRow>[] = [
  { key: "userId", label: "ID", visible: true, sortable: true },
  { key: "username", label: "Name", visible: true, sortable: true },
  { key: "email", label: "Email", visible: true, sortable: false },
  {
    key: "signUpMethod",
    label: "Sign Up Method",
    visible: false,
    sortable: false,
  },
  { key: "isTwoFactorEnabled", label: "2FA", visible: false, sortable: false },
  { key: "roles", label: "Roles", visible: true, sortable: false },
  // { key: "enabled", label: "Active", visible: true, sortable: false },
  {
    key: "createdDate",
    label: "Created Date",
    visible: false,
    sortable: true,
    isDate: true,
  },
];
export const AdminUserList = () => {
  // State
  const [selectedUserId, setSelectedUserId] = useState<number | null>(null);
  const [viewModalOpen, setViewModalOpen] = useState(false);
  const [editModalOpen, setEditModalOpen] = useState(false);
  const [userToEdit, setUserToEdit] = useState<number | null>(null);
  const [searchCriteria, setSearchCriteria] =
    useState<AdminUserViewFilterFormData>({
      page: 0,
      size: 10,
      sortBy: "username",
      sortDirection: "asc",
    });
  const [showFilter, setShowFilter] = useState(false);
  const [searchDebounce, setSearchDebounce] = useState("");

  // Mutations & Queries

  const {
    filterOptions,
    isLoading: filterLoading,
    error: filterError,
    refetch: filterRefetch,
  } = useQueryAdminUserViewFilterOptions();

  const {
    users,
    pagination,
    isLoading: userListLoading,
    error: userListError,
    refetch: userListRefetch,
  } = useQueryAdminUserView(searchCriteria);

  // In your component where you're preparing the data for the table
  const tableRows: AdminUserListRow[] = users.map((user: AdminUserView) => ({
    userId: user.userId,
    username: user.username,
    email: user.email,
    signUpMethod: user.signUpMethod,
    isTwoFactorEnabled: user.isTwoFactorEnabled,
    roles: user.roles.map((role) => role.roleName).join(", "), // Join role names
    enabled: user.enabled,
    createdDate: user.createdDate,
  }));

  // Handlers
  const handleViewUser = useCallback((id: string | number) => {
    const userId = typeof id === "string" ? parseInt(id, 10) : id;
    if (!isNaN(userId)) {
      setSelectedUserId(userId);
      setViewModalOpen(true);
    }
  }, []);

  const handleEditUser = useCallback(
    (id: string | number) => {
      const userId = typeof id === "string" ? parseInt(id, 10) : id;
      if (!isNaN(userId)) {
        const user = users.find((u) => u.userId === userId);
        if (user) {
          setUserToEdit(user.userId);
          setEditModalOpen(true);
        }
      }
    },
    [users]
  );

  const handleEditSuccess = () => {
    setEditModalOpen(false);
    setUserToEdit(null);
    userListRefetch();
  };

  const handleFilterSubmit = (criteria: AdminUserViewFilterFormData) => {
    setSearchCriteria(criteria);
    setShowFilter(false);
  };

  const handleRefetchAll = () => {
    userListRefetch();
    filterRefetch();
  };

  const handleSearchChange = (criteria: AdminUserViewFilterFormData) => {
    setSearchCriteria(criteria);
  };

  const handlePageChange = (page: number) => {
    setSearchCriteria((prev) => ({ ...prev, page }));
  };

  const handlePageSizeChange = (size: number) => {
    setSearchCriteria((prev) => ({ ...prev, size, page: 0 }));
  };

  const activeFiltersCount = useMemo(() => {
    return (
      Object.keys(searchCriteria) as (keyof AdminUserViewSearchCriteria)[]
    ).filter(
      (key) =>
        key !== "page" &&
        key !== "size" &&
        key !== "sortBy" &&
        key !== "sortDirection" &&
        searchCriteria[key] !== undefined
    ).length;
  }, [searchCriteria]);

  // Columns
  const columns: ColumnDef<AdminUserListRow>[] = useMemo(
    () => [
      createIndexColumn<AdminUserListRow>(),
      ...generateColumns<AdminUserListRow>(COLUMN_CONFIGS),
      createIsActiveColumn<AdminUserListRow>("enabled"),
      createActionsColumn<AdminUserListRow>(
        handleViewUser,
        undefined,
        handleEditUser,
        "User"
      ),
    ],
    [handleViewUser, handleEditUser]
  );

  // Use the generic table hook
  const { table, toggleableColumns, visibleCount, totalCount, columnActions } =
    useDataTable<AdminUserListRow, AdminUserViewSearchCriteria>({
      data: tableRows as AdminUserListRow[],
      columns,
      columnConfigs: COLUMN_CONFIGS,
      pagination,
      searchCriteria,
      onSearchChange: handleSearchChange,
      getRowId: (row) => String(row.userId),
    });

  // Effects
  useEffect(() => {
    const timer = setTimeout(() => {
      setSearchCriteria((prev) => ({
        ...prev,
        username: searchDebounce || undefined,
        page: 0,
      }));
    }, 500);

    return () => clearTimeout(timer);
  }, [searchDebounce]);

  // Render filter form
  const renderFilterForm = () => {
    if (filterLoading) {
      return (
        <div className="flex flex-col items-center justify-center py-6 gap-2 text-sm text-muted-foreground">
          <Loader2 className="w-5 h-5 animate-spin" />
          <span>Loading Filters...</span>
        </div>
      );
    }

    if (filterError) {
      return (
        <Alert variant="destructive">
          <AlertTitle>Error loading filters</AlertTitle>
          <AlertDescription>
            Please check your network or try refreshing.
          </AlertDescription>
        </Alert>
      );
    }

    if (filterOptions) {
      return (
        <AdminUserViewFilterForm
          filterOptions={filterOptions as AdminUserViewFilterOptions}
          defaultValues={searchCriteria}
          onSubmit={handleFilterSubmit}
          currentSearch={searchDebounce}
        />
      );
    }

    return null;
  };

  return (
    <div className="space-y-4">
      {/* Table Controls */}
      <TableControls
        searchValue={searchDebounce}
        onSearchChange={setSearchDebounce}
        searchPlaceholder="Search users..."
        showFilter={showFilter}
        onFilterToggle={() => setShowFilter(!showFilter)}
        activeFiltersCount={activeFiltersCount}
        filterLoading={filterLoading}
        toggleableColumns={toggleableColumns}
        visibleCount={visibleCount}
        totalCount={totalCount}
        columnConfigs={COLUMN_CONFIGS}
        onShowAllColumns={columnActions.showAll}
        onHideAllColumns={columnActions.hideAll}
        onResetColumns={columnActions.resetVisibility}
        onRefresh={handleRefetchAll}
        isRefreshing={userListLoading}
      >
        {renderFilterForm()}
      </TableControls>

      {/* Data Table */}
      <DataTable
        table={table}
        columns={columns}
        data={tableRows as AdminUserListRow[]}
        pagination={pagination}
        isLoading={userListLoading}
        error={userListError}
        onRefresh={handleRefetchAll}
        onPageChange={handlePageChange}
        onPageSizeChange={handlePageSizeChange}
        title="Users"
        emptyMessage="No users found."
      />

      {/* User View Modal */}
      {selectedUserId && (
        <AdminUserModal
          userId={selectedUserId}
          open={viewModalOpen}
          onOpenChange={setViewModalOpen}
        />
      )}
      {/* Edit User Modal */}
      <Dialog open={editModalOpen} onOpenChange={setEditModalOpen}>
        <DialogContent className="max-w-3xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="text-2xl">Update User</DialogTitle>
            <DialogDescription>
              Update the user information below. Leave the password field empty
              to keep the current password.
            </DialogDescription>
          </DialogHeader>
          {userToEdit && (
            <CreateUserForm userId={userToEdit} onSuccess={handleEditSuccess} />
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
};
