// hooks/useDataTable.ts
import { useState, useMemo } from 'react';
import { ColumnDef, SortingState, VisibilityState, useReactTable, getCoreRowModel } from '@tanstack/react-table';
import { TableColumnConfig } from '../generateColumns';

// export interface TableColumnConfig<T> {
//   key: keyof T;
//   label: string;
//   visible: boolean;
//   sortable: boolean;
//   isDate?: boolean;
// }

export interface PaginationInfo {
  currentPage: number;
  pageSize: number;
  totalPages: number;
  totalElements: number;
  hasNext: boolean;
  hasPrevious: boolean;
}

// Make SearchCriteria generic to accept specific sort options
export interface SearchCriteria<TSortBy = string> {
  page?: number;
  size?: number;
  sortBy?: TSortBy;
  sortDirection?: 'asc' | 'desc';
  // [key: string]: any;
}

interface UseDataTableProps<T, TSearchCriteria extends SearchCriteria = SearchCriteria> {
  data: T[];
  columns: ColumnDef<T>[];
  columnConfigs: TableColumnConfig<T>[];
  pagination: PaginationInfo;
  searchCriteria: TSearchCriteria;
  onSearchChange: (criteria: TSearchCriteria) => void;
  getRowId?: (row: T) => string;
}

export function useDataTable<T, TSearchCriteria extends SearchCriteria = SearchCriteria>({
  data,
  columns,
  columnConfigs,
  pagination,
  searchCriteria,
  onSearchChange,
  getRowId = (row: T) => String((row as Record<string, unknown>).id),
}: UseDataTableProps<T, TSearchCriteria>) {
  const defaultVisibility = useMemo(
    () => Object.fromEntries(columnConfigs.map((col) => [col.key, col.visible])) as VisibilityState,
    [columnConfigs]
  );

  const [columnVisibility, setColumnVisibility] = useState<VisibilityState>(defaultVisibility);
  const [sorting, setSorting] = useState<SortingState>([]);

  const table = useReactTable({
    data,
    columns,
    getCoreRowModel: getCoreRowModel(),
    getRowId,
    manualSorting: true,
    manualPagination: true,
    state: {
      columnVisibility,
      sorting,
      pagination: {
        pageIndex: searchCriteria.page ?? 0,
        pageSize: searchCriteria.size ?? 10,
      },
    },
    pageCount: pagination?.totalPages ?? -1,
    onColumnVisibilityChange: setColumnVisibility,
    onSortingChange: (updater) => {
      const newSorting = typeof updater === 'function' ? updater(sorting) : updater;
      setSorting(newSorting);

      const firstSort = newSorting[0];
      if (firstSort) {
        onSearchChange({
          ...searchCriteria,
          sortBy: firstSort.id as TSearchCriteria['sortBy'],
          sortDirection: firstSort.desc ? 'desc' : 'asc',
          page: 0,
        });
      }
    },
    onPaginationChange: (updater) => {
      const newPagination = typeof updater === 'function'
        ? updater({
          pageIndex: searchCriteria.page ?? 0,
          pageSize: searchCriteria.size ?? 10,
        })
        : updater;

      onSearchChange({
        ...searchCriteria,
        page: newPagination.pageIndex,
        size: newPagination.pageSize,
      });
    },
  });

  const toggleableColumns = table.getAllColumns().filter(
    (col) => col.getCanHide() && !['index', 'actions'].includes(col.id)
  );

  const visibleCount = toggleableColumns.filter((col) => col.getIsVisible()).length;
  const totalCount = toggleableColumns.length;

  const columnActions = {
    showAll: () => toggleableColumns.forEach((col) => col.toggleVisibility(true)),
    hideAll: () => toggleableColumns.forEach((col) => col.toggleVisibility(false)),
    resetVisibility: () => setColumnVisibility(defaultVisibility),
  };

  return {
    table,
    columnVisibility,
    sorting,
    toggleableColumns,
    visibleCount,
    totalCount,
    columnActions,
  };
}