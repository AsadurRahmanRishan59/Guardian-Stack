// MotorTariffList.tsx - Refactored using reusable components
"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { ColumnDef } from "@tanstack/react-table";

// Import reusable components
import { useDataTable, TableColumnConfig } from "@/hooks/useDataTable";
import { TableControls } from "@/components/table/TableControls";
import { DataTable } from "@/components/table/DataTable";
import {
  createActionsColumn,
  createIndexColumn,
  createIsActiveColumn,
  generateColumns,
} from "@/lib/generateColumns";
import {
  MotorTariffAdminView,
  MotorTariffSearchCriteria,
} from "@/features/tariff-motor/motor.tariff.types";

import {
  useDeleteMotorTariff,
  useQueryMotorTariffs,
} from "@/features/tariff-motor/motor.tariff.react-query";
import { MotorTariffFilterForm } from "@/features/tariff-motor/components/MotorTariffFilterForm";
import MotorTariffViewModal from "@/features/tariff-motor/components/MotorTariffViewModal";
import { MotorTariffFilterFormValues } from "@/features/tariff-motor/motor.tariff.schema";
import MotorTariffPatchModal from "./MotorTariffPatchModal";

const COLUMN_CONFIGS: TableColumnConfig<MotorTariffAdminView>[] = [
  { key: "tariffKey", label: "ID", visible: true, sortable: true },
  { key: "tariffType", label: "Type", visible: true, sortable: true },
  { key: "groupOfVehicle", label: "Group", visible: false, sortable: true },
  {
    key: "typeOfVehicle",
    label: "Type of Vehicle",
    visible: true,
    sortable: true,
  },
  { key: "category", label: "Category", visible: true, sortable: true },
  { key: "ownDpBasic", label: "Own Damage", visible: true, sortable: false },
  {
    key: "fullInsValue",
    label: "Full Insurance",
    visible: true,
    sortable: false,
  },
  {
    key: "actLiability",
    label: "Act Liability",
    visible: true,
    sortable: false,
  },
];
export const MotorTariffList = () => {
  // State
  const [selectedTariffKey, setSelectedTariffKey] = useState<number | null>(
    null
  );
  const [viewModalOpen, setViewModalOpen] = useState(false);
  const [patchRateModalOpen, setPatchRateModalOpen] = useState(false);
  const [searchCriteria, setSearchCriteria] =
    useState<MotorTariffFilterFormValues>({
      page: 0,
      size: 10,
      sortBy: "tariffKey",
      sortDirection: "asc",
    });
  const [showFilter, setShowFilter] = useState(false);
  const [searchDebounce, setSearchDebounce] = useState("");

  // Mutations & Queries
  const deleteMotorTariff = useDeleteMotorTariff().mutateAsync;

  const {
    motorTariffs,
    pagination,
    isLoading: motorTariffListLoading,
    error: motorTariffListError,
    refetch: motorTariffListRefetch,
  } = useQueryMotorTariffs(searchCriteria);

  // Handlers
  const handleViewMotorTariff = useCallback((id: string | number) => {
    const tariffKey = typeof id === "string" ? parseInt(id, 10) : id;
    if (!isNaN(tariffKey)) {
      setSelectedTariffKey(tariffKey);
      setViewModalOpen(true);
    }
  }, []);

  const handlePatchRate = useCallback((id: string | number) => {
    const tariffKey = typeof id === "string" ? parseInt(id, 10) : id;
    if (!isNaN(tariffKey)) {
      setSelectedTariffKey(tariffKey);
      setPatchRateModalOpen(true);
    }
  }, []);

  const handleDeleteMotorTariff = useCallback(
    async (id: string | number) => {
      const tariffKey = typeof id === "string" ? parseInt(id, 10) : id;
      if (!isNaN(tariffKey)) {
        await deleteMotorTariff(tariffKey);
      }
    },
    [deleteMotorTariff]
  );

  const handleFilterSubmit = (criteria: MotorTariffFilterFormValues) => {
    setSearchCriteria(criteria);
    setShowFilter(false);
  };

  const handleRefetchAll = () => {
    motorTariffListRefetch();
  };

  const handleSearchChange = (criteria: MotorTariffFilterFormValues) => {
    setSearchCriteria(criteria);
  };

  const handlePageChange = (page: number) => {
    setSearchCriteria((prev) => ({ ...prev, page }));
  };

  const handlePageSizeChange = (size: number) => {
    setSearchCriteria((prev) => ({ ...prev, size, page: 0 }));
  };

  const activeFiltersCount = useMemo(() => {
    return Object.keys(searchCriteria).filter(
      (key) =>
        key !== "page" &&
        key !== "size" &&
        key !== "sortBy" &&
        key !== "sortDirection" &&
        searchCriteria[key as keyof MotorTariffSearchCriteria] !== undefined
    ).length;
  }, [searchCriteria]);

  // Columns
  const columns: ColumnDef<MotorTariffAdminView>[] = useMemo(
    () => [
      createIndexColumn<MotorTariffAdminView>(),
      ...generateColumns<MotorTariffAdminView>(COLUMN_CONFIGS),
      createIsActiveColumn<MotorTariffAdminView>("isActive"),
      createActionsColumn<MotorTariffAdminView>(
        handleViewMotorTariff,
        handleDeleteMotorTariff,
        handlePatchRate,
        "MotorTariff"
      ),
    ],
    [handleViewMotorTariff, handleDeleteMotorTariff,handlePatchRate]
  );

  // Use the generic table hook
  const { table, toggleableColumns, visibleCount, totalCount, columnActions } =
    useDataTable<MotorTariffAdminView, MotorTariffSearchCriteria>({
      data: motorTariffs,
      columns,
      columnConfigs: COLUMN_CONFIGS,
      pagination,
      searchCriteria,
      onSearchChange: handleSearchChange,
      getRowId: (row) => String(row.tariffKey),
    });

  // Effects
  useEffect(() => {
    const timer = setTimeout(() => {
      setSearchCriteria((prev) => ({
        ...prev,
        tariffKey: searchDebounce ? Number(searchDebounce) : undefined,
        page: 0,
      }));
    }, 500);

    return () => clearTimeout(timer);
  }, [searchDebounce]);

  return (
    <div className="space-y-4">
      {/* Table Controls */}
      <TableControls
        searchValue={searchDebounce}
        onSearchChange={setSearchDebounce}
        searchPlaceholder="Search motorTariffs..."
        showFilter={showFilter}
        onFilterToggle={() => setShowFilter(!showFilter)}
        activeFiltersCount={activeFiltersCount}
        toggleableColumns={toggleableColumns}
        visibleCount={visibleCount}
        totalCount={totalCount}
        columnConfigs={COLUMN_CONFIGS}
        onShowAllColumns={columnActions.showAll}
        onHideAllColumns={columnActions.hideAll}
        onResetColumns={columnActions.resetVisibility}
        onRefresh={handleRefetchAll}
        isRefreshing={motorTariffListLoading}
      >
        <MotorTariffFilterForm
          defaultValues={searchCriteria}
          onSubmit={handleFilterSubmit}
          currentSearch={searchDebounce}
        />
      </TableControls>

      {/* Data Table */}
      <DataTable
        table={table}
        columns={columns}
        data={motorTariffs}
        pagination={pagination}
        isLoading={motorTariffListLoading}
        error={motorTariffListError}
        onRefresh={handleRefetchAll}
        onPageChange={handlePageChange}
        onPageSizeChange={handlePageSizeChange}
        title="MotorTariffs"
        emptyMessage="No motorTariffs found."
      />

      {/* MotorTariff View Modal */}
      {selectedTariffKey && (
        <MotorTariffViewModal
          tariffKey={selectedTariffKey}
          open={viewModalOpen}
          onOpenChange={setViewModalOpen}
        />
      )}

       {/* Motor Tariff Patch Modal */}
      {selectedTariffKey && (
        <MotorTariffPatchModal
          tariffKey={selectedTariffKey}
          open={patchRateModalOpen}
          onOpenChange={setPatchRateModalOpen}
        />
      )}
    </div>
  );
};
