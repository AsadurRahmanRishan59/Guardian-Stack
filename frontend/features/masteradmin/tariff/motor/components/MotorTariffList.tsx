// features/masteradmin/tariff/motor/MotorTariffList.tsx
"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { ColumnDef } from "@tanstack/react-table";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

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
  useMotorTariffs,
  useDeleteMotorTariff,
  useMotorTariffById,
} from "../motor.tariff.react-query";
import { MotorTariffFilterFormValues } from "../motor.tariff.schema";
import { MotorTariffSearchCriteria, MotorTariffShortView } from "../motor.tariff.types";
import MotorTariffFilterForm from "./MotorTariffFilterForm";
import { MotorTariffViewModal } from "./MotorTariffViewModal";
import { MotorTariffForm } from "./MotorTariffForm";
import { ConfirmDialog } from "@/components/confirm-dialog";

// ── Table row shape ────────────────────────────────────────────────────────────
interface MotorTariffRow {
  tariffKey: number;
  tariffType: string;
  groupOfVehicle: string;
  typeOfVehicle: string;
  category: string;
  ownDpBasic: number;
  fullInsValue: number;
  actLiability: number;
  isActive: boolean;
}

// ── Column definitions ─────────────────────────────────────────────────────────
const COLUMN_CONFIGS: TableColumnConfig<MotorTariffRow>[] = [
  { key: "tariffKey", label: "ID", visible: true, sortable: true },
  { key: "tariffType", label: "Tariff Type", visible: true, sortable: true },
  { key: "groupOfVehicle", label: "Vehicle Group", visible: true, sortable: true },
  { key: "typeOfVehicle", label: "Vehicle Type", visible: true, sortable: true },
  { key: "category", label: "Category / CC", visible: true, sortable: true },
  { key: "ownDpBasic", label: "Own DP Basic (৳)", visible: true, sortable: false },
  { key: "fullInsValue", label: "Full Ins. Value (%)", visible: false, sortable: false },
  { key: "actLiability", label: "Act Liability (৳)", visible: false, sortable: false },
  {
    key: "isActive",
    label: "Status",
    visible: true,
    sortable: false,
    isBoolean: true,
    trueLabel: "Active",
    falseLabel: "Inactive",
    isNegative: false,
  },
];

// ── Component ──────────────────────────────────────────────────────────────────
export function MotorTariffList() {
  // ── Modal state ──
  const [viewTariffKey, setViewTariffKey] = useState<number | null>(null);
  const [viewModalOpen, setViewModalOpen] = useState(false);

  const [editTariffKey, setEditTariffKey] = useState<number | null>(null);
  const [editModalOpen, setEditModalOpen] = useState(false);

  const [deleteTariffKey, setDeleteTariffKey] = useState<number | null>(null);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);

  // ── Search state ──
  const [searchCriteria, setSearchCriteria] =
    useState<MotorTariffFilterFormValues>({
      page: 0,
      size: 10,
      sortBy: "tariffKey",
      sortDirection: "asc",
    });
  const [showFilter, setShowFilter] = useState(false);
  const [searchDebounce, setSearchDebounce] = useState("");

  // ── Data ──
  const { motorTariffs, pagination, isLoading, error, refetch } =
    useMotorTariffs(searchCriteria);

  const deleteMutation = useDeleteMotorTariff();

  // Prefetch edit data when key is set
  const { data: editData } = useMotorTariffById(editTariffKey ?? undefined);

  // ── Table rows ──
  const tableRows: MotorTariffRow[] = motorTariffs.map(
    (t: MotorTariffShortView) => ({
      tariffKey: t.tariffKey,
      tariffType: t.tariffType,
      groupOfVehicle: t.groupOfVehicle,
      typeOfVehicle: t.typeOfVehicle,
      category: t.category,
      ownDpBasic: t.ownDpBasic,
      fullInsValue: t.fullInsValue,
      actLiability: t.actLiability,
      isActive: t.isActive,
    })
  );

  // ── Handlers ──
  const handleView = useCallback((id: string | number) => {
    const key = Number(id);
    if (!isNaN(key)) {
      setViewTariffKey(key);
      setViewModalOpen(true);
    }
  }, []);

  const handleEdit = useCallback((id: string | number) => {
    const key = Number(id);
    if (!isNaN(key)) {
      setEditTariffKey(key);
      setEditModalOpen(true);
    }
  }, []);

  const handleDelete = useCallback((id: string | number) => {
    const key = Number(id);
    if (!isNaN(key)) {
      setDeleteTariffKey(key);
      setDeleteDialogOpen(true);
    }
  }, []);

  const handleConfirmDelete = () => {
    if (deleteTariffKey != null) {
      deleteMutation.mutate(deleteTariffKey, {
        onSuccess: () => {
          setDeleteDialogOpen(false);
          setDeleteTariffKey(null);
          refetch();
        },
      });
    }
  };

  const handleFilterSubmit = (criteria: MotorTariffFilterFormValues) => {
    setSearchCriteria(criteria);
    setShowFilter(false);
  };

  const handleSearchChange = (criteria: MotorTariffFilterFormValues) => {
    setSearchCriteria(criteria);
  };

  const handlePageChange = (page: number) =>
    setSearchCriteria((prev) => ({ ...prev, page }));

  const handlePageSizeChange = (size: number) =>
    setSearchCriteria((prev) => ({ ...prev, size, page: 0 }));

  // Active filter count (exclude pagination/sort keys)
  const activeFiltersCount = useMemo(() => {
    const ignored = new Set(["page", "size", "sortBy", "sortDirection"]);
    return Object.keys(searchCriteria).filter(
      (k) =>
        !ignored.has(k) &&
        (searchCriteria as Record<string, unknown>)[k] !== undefined
    ).length;
  }, [searchCriteria]);

  // Debounced tariffKey search
  useEffect(() => {
    const timer = setTimeout(() => {
      const parsed = parseInt(searchDebounce, 10);
      setSearchCriteria((prev) => ({
        ...prev,
        tariffKey: searchDebounce && !isNaN(parsed) ? parsed : undefined,
        page: 0,
      }));
    }, 500);
    return () => clearTimeout(timer);
  }, [searchDebounce]);

  // ── Columns ──
  const columns: ColumnDef<MotorTariffRow>[] = useMemo(
    () => [
      createIndexColumn<MotorTariffRow>(),
      ...generateColumns<MotorTariffRow>(COLUMN_CONFIGS),
      createActionsColumn<MotorTariffRow>(
        handleView,
        handleDelete,
        handleEdit,
        "Tariff"
      ),
    ],
    [handleView, handleDelete, handleEdit]
  );

  const { table, toggleableColumns, visibleCount, totalCount, columnActions } =
    useDataTable<MotorTariffRow, MotorTariffSearchCriteria>({
      data: tableRows,
      columns,
      columnConfigs: COLUMN_CONFIGS,
      pagination,
      searchCriteria,
      onSearchChange: handleSearchChange,
      getRowId: (row) => String(row.tariffKey),
    });

  return (
    <div className="space-y-2">
      <TableControls
        searchValue={searchDebounce}
        onSearchChange={setSearchDebounce}
        searchPlaceholder="Search tariffs…"
        showFilter={showFilter}
        onFilterToggle={() => setShowFilter(!showFilter)}
        activeFiltersCount={activeFiltersCount}
        filterLoading={false}
        toggleableColumns={toggleableColumns}
        visibleCount={visibleCount}
        totalCount={totalCount}
        columnConfigs={COLUMN_CONFIGS}
        onShowAllColumns={columnActions.showAll}
        onHideAllColumns={columnActions.hideAll}
        onResetColumns={columnActions.resetVisibility}
        onRefresh={refetch}
        isRefreshing={isLoading}
      >
        <MotorTariffFilterForm
          defaultValues={searchCriteria}
          onSubmit={handleFilterSubmit}
        />
      </TableControls>

      <DataTable
        table={table}
        columns={columns}
        data={tableRows}
        pagination={pagination}
        isLoading={isLoading}
        error={error}
        onRefresh={refetch}
        onPageChange={handlePageChange}
        onPageSizeChange={handlePageSizeChange}
        title="Motor Tariffs"
        emptyMessage="No motor tariffs found."
      />

      {/* ── View Modal ── */}
      {viewTariffKey && (
        <MotorTariffViewModal
          tariffKey={viewTariffKey}
          open={viewModalOpen}
          onOpenChange={setViewModalOpen}
        />
      )}

      {/* ── Edit Modal ── */}
      <Dialog open={editModalOpen} onOpenChange={setEditModalOpen}>
        <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto border-gs-line bg-surface-card">
          <DialogHeader>
            <DialogTitle className="text-xl font-head text-t1">Edit Motor Tariff</DialogTitle>
            <DialogDescription className="text-t3">
              Update the tariff details below. The unique vehicle combination
              (Type → Group → Type → Category) cannot duplicate an existing entry.
            </DialogDescription>
          </DialogHeader>
          {editTariffKey && (
            <MotorTariffForm
              tariffKey={editTariffKey}
              initialData={editData}
              onSuccess={() => {
                setEditModalOpen(false);
                setEditTariffKey(null);
                refetch();
              }}
            />
          )}
        </DialogContent>
      </Dialog>

      {/* ── Delete Confirm ── */}
      <ConfirmDialog
        open={deleteDialogOpen}
        onOpenChange={setDeleteDialogOpen}
        onConfirm={handleConfirmDelete}
        title="Delete Motor Tariff?"
        description={`Tariff #${deleteTariffKey} will be permanently deleted. This action cannot be undone.`}
        confirmText="Delete Tariff"
      />
    </div>
  );
}