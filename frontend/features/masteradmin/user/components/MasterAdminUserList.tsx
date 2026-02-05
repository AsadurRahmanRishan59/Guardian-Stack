//features/admin/user/components/AdminUserList.tsx
"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { ColumnDef } from "@tanstack/react-table";
import { Loader2 } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

// Import reusable components
import { useDataTable } from "@/lib/hooks/useDataTable";
import { TableControls } from "@/components/table/TableControls";
import { DataTable } from "@/components/table/DataTable";
import {
  createActionsColumn,
  createIndexColumn,
  generateColumns,
  TableColumnConfig,
} from "@/lib/generateColumns";

import {
  MasterAdminUserView,
  MasterAdminUserViewFilterOptions,
  MasterAdminUserViewSearchCriteria,
  SignUpMethod,
} from "../user.types";
import {
  useQueryAdminUserView,
  useQueryAdminUserViewFilterOptions,
} from "../user.react.query";
import { MasterAdminUserViewFilterFormData } from "../user.schema";
import { MasterAdminUserViewFilterForm } from "./MasterAdminUserViewFilterForm";
import AdminUserModal from "./AdminUserModal";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { CreateUserForm } from "./CreateUserForm";

interface MasterAdminUserViewListRow {
  userId: number;
  username: string;
  email: string;
  enabled: boolean;
  accountLocked: boolean;
  accountExpired: boolean;
  credentialExpired: boolean;
  signUpMethod: SignUpMethod;
  roles: string;
  createdAt: string;
  createdBy: string;
}

const COLUMN_CONFIGS: TableColumnConfig<MasterAdminUserViewListRow>[] = [
  { key: "userId", label: "ID", visible: true, sortable: true },
  { key: "username", label: "Name", visible: true, sortable: true },
  { key: "email", label: "Email", visible: true, sortable: false },
  {
    key: "enabled",
    label: "Status",
    visible: true,
    sortable: false,
    isBoolean: true,
    trueLabel: "Active",
    falseLabel: "Inactive",
    isNegative: false, // true = Yellow/Primary
  },
  {
    key: "accountLocked",
    label: "Security",
    visible: false,
    sortable: false,
    isBoolean: true,
    trueLabel: "Locked",
    falseLabel: "Unlocked",
    isNegative: true, // true = Red/Destructive
  },
  {
    key: "accountExpired",
    label: "Account",
    visible: false,
    isBoolean: true,
    isNegative: true,
    trueLabel: "Expired",
    falseLabel: "Valid",
  },
  {
    key: "credentialExpired",
    label: "Credentials",
    visible: false,
    isBoolean: true,
    isNegative: true,
    trueLabel: "Expired",
    falseLabel: "Valid",
  },
  { key: "roles", label: "Roles", visible: true, sortable: false },
  { key: "signUpMethod", label: "Sign Up Method", visible: true, sortable: false },
  {
    key: "createdAt",
    label: "Created At",
    visible: false,
    sortable: true,
    isDate: true,
  },
  {
    key: "createdBy",
    label: "Created By",
    visible: false,
    sortable: true,
    isDate: false,
  },
];
export const MasterAdminUserList = () => {
  // State
  const [selectedUserId, setSelectedUserId] = useState<number | null>(null);
  const [viewModalOpen, setViewModalOpen] = useState(false);
  const [editModalOpen, setEditModalOpen] = useState(false);
  const [userToEdit, setUserToEdit] = useState<number | null>(null);
  const [searchCriteria, setSearchCriteria] =
    useState<MasterAdminUserViewFilterFormData>({
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
  const tableRows: MasterAdminUserViewListRow[] = users.map(
    (user: MasterAdminUserView) => ({
      userId: user.userId,
      username: user.username,
      email: user.email,
      enabled: user.enabled,
      accountLocked: user.accountLocked,
      accountExpired: user.accountExpired,
      credentialExpired: user.credentialExpired,
      signUpMethod: user.signUpMethod,
      roles: user.roles.map((role) => role).join(", "), // Join
      createdAt: user.createdAt,
      createdBy: user.createdBy,
    }),
  );

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
    [users],
  );

  const handleEditSuccess = () => {
    setEditModalOpen(false);
    setUserToEdit(null);
    userListRefetch();
  };

  const handleFilterSubmit = (criteria: MasterAdminUserViewFilterFormData) => {
    setSearchCriteria(criteria);
    setShowFilter(false);
  };

  const handleRefetchAll = () => {
    userListRefetch();
    filterRefetch();
  };

  const handleSearchChange = (criteria: MasterAdminUserViewFilterFormData) => {
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
      Object.keys(searchCriteria) as (keyof MasterAdminUserViewSearchCriteria)[]
    ).filter(
      (key) =>
        key !== "page" &&
        key !== "size" &&
        key !== "sortBy" &&
        key !== "sortDirection" &&
        searchCriteria[key] !== undefined,
    ).length;
  }, [searchCriteria]);

  // Columns
  const columns: ColumnDef<MasterAdminUserViewListRow>[] = useMemo(
    () => [
      createIndexColumn<MasterAdminUserViewListRow>(),
      ...generateColumns<MasterAdminUserViewListRow>(COLUMN_CONFIGS),
      createActionsColumn<MasterAdminUserViewListRow>(
        handleViewUser,
        undefined,
        handleEditUser,
        "User",
      ),
    ],
    [handleViewUser, handleEditUser],
  );

  // Use the generic table hook
  const { table, toggleableColumns, visibleCount, totalCount, columnActions } =
    useDataTable<MasterAdminUserViewListRow, MasterAdminUserViewSearchCriteria>(
      {
        data: tableRows as MasterAdminUserViewListRow[],
        columns,
        columnConfigs: COLUMN_CONFIGS,
        pagination,
        searchCriteria,
        onSearchChange: handleSearchChange,
        getRowId: (row) => String(row.userId),
      },
    );

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
        <MasterAdminUserViewFilterForm
          filterOptions={filterOptions as MasterAdminUserViewFilterOptions}
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
        data={tableRows as MasterAdminUserViewListRow[]}
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
