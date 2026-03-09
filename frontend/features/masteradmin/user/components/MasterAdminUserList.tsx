// features/admin/user/components/MasterAdminUserList.tsx
"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { ColumnDef } from "@tanstack/react-table";
import { Loader2 } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

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
import AdminUserModal from "./MasterAdminUserModal";
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
    isNegative: false,
  },
  {
    key: "accountLocked",
    label: "Security",
    visible: false,
    sortable: false,
    isBoolean: true,
    trueLabel: "Locked",
    falseLabel: "Unlocked",
    isNegative: true,
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
      roles: user.roles.join(", "),
      createdAt: user.createdAt,
      createdBy: user.createdBy,
    })
  );

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

  const handlePageChange = (page: number) =>
    setSearchCriteria((prev) => ({ ...prev, page }));

  const handlePageSizeChange = (size: number) =>
    setSearchCriteria((prev) => ({ ...prev, size, page: 0 }));

  const activeFiltersCount = useMemo(() => {
    return (
      Object.keys(searchCriteria) as (keyof MasterAdminUserViewSearchCriteria)[]
    ).filter(
      (key) =>
        key !== "page" &&
        key !== "size" &&
        key !== "sortBy" &&
        key !== "sortDirection" &&
        searchCriteria[key] !== undefined
    ).length;
  }, [searchCriteria]);

  const columns: ColumnDef<MasterAdminUserViewListRow>[] = useMemo(
    () => [
      createIndexColumn<MasterAdminUserViewListRow>(),
      ...generateColumns<MasterAdminUserViewListRow>(COLUMN_CONFIGS),
      createActionsColumn<MasterAdminUserViewListRow>(
        handleViewUser,
        undefined,
        handleEditUser,
        "User"
      ),
    ],
    [handleViewUser, handleEditUser]
  );

  const { table, toggleableColumns, visibleCount, totalCount, columnActions } =
    useDataTable<MasterAdminUserViewListRow, MasterAdminUserViewSearchCriteria>({
      data: tableRows,
      columns,
      columnConfigs: COLUMN_CONFIGS,
      pagination,
      searchCriteria,
      onSearchChange: handleSearchChange,
      getRowId: (row) => String(row.userId),
    });

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

  const renderFilterForm = () => {
    if (filterLoading) {
      return (
        <div className="flex items-center justify-center py-6 gap-2 text-sm text-t3">
          <Loader2 className="w-4 h-4 animate-spin text-brand" />
          <span>Loading filters…</span>
        </div>
      );
    }
    if (filterError) {
      return (
        <Alert variant="destructive" className="border-destructive/30 bg-destructive/10">
          <AlertTitle className="text-destructive">Error loading filters</AlertTitle>
          <AlertDescription className="text-destructive/80">
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
    <div className="space-y-2">
      <TableControls
        searchValue={searchDebounce}
        onSearchChange={setSearchDebounce}
        searchPlaceholder="Search users…"
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

      <DataTable
        table={table}
        columns={columns}
        data={tableRows}
        pagination={pagination}
        isLoading={userListLoading}
        error={userListError}
        onRefresh={handleRefetchAll}
        onPageChange={handlePageChange}
        onPageSizeChange={handlePageSizeChange}
        title="Users"
        emptyMessage="No users found."
      />

      {selectedUserId && (
        <AdminUserModal
          userId={selectedUserId}
          open={viewModalOpen}
          onOpenChange={setViewModalOpen}
        />
      )}

      <Dialog open={editModalOpen} onOpenChange={setEditModalOpen}>
        <DialogContent className="max-w-3xl max-h-[90vh] overflow-y-auto border-gs-line bg-surface-card">
          <DialogHeader>
            <DialogTitle className="text-xl font-head text-t1">Update User</DialogTitle>
            <DialogDescription className="text-t3">
              Update the user information below. Leave the password field empty to keep
              the current password.
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