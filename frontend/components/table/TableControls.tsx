// 6. Table Controls Component
// components/table/TableControls.tsx
import React from 'react';
import { RefreshCw } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';

import { TableColumnConfig } from '@/lib/hooks/useDataTable';
import { TableSearch } from './TableSearch';
import { FilterToggle } from './FilterToggle';
import { ColumnVisibility } from './ColumnVisibility';
import { Column } from '@tanstack/react-table';

interface TableControlsProps<T> {
  searchValue: string;
  onSearchChange: (value: string) => void;
  searchPlaceholder?: string;
  showFilter: boolean;
  onFilterToggle: () => void;
  activeFiltersCount: number;
  filterLoading?: boolean;
  toggleableColumns: Column<T, unknown>[];
  visibleCount: number;
  totalCount: number;
  columnConfigs: TableColumnConfig<T>[];
  onShowAllColumns: () => void;
  onHideAllColumns: () => void;
  onResetColumns: () => void;
  onRefresh: () => void;
  isRefreshing?: boolean;
  children?: React.ReactNode; // For filter form
}

export function TableControls<T>({
  searchValue,
  onSearchChange,
  searchPlaceholder,
  showFilter,
  onFilterToggle,
  activeFiltersCount,
  filterLoading,
  toggleableColumns,
  visibleCount,
  totalCount,
  columnConfigs,
  onShowAllColumns,
  onHideAllColumns,
  onResetColumns,
  onRefresh,
  isRefreshing,
  children,
}: TableControlsProps<T>) {
  return (
    <Card>
      <CardContent className="pt-6">
        <div className="flex gap-4 items-center">
          <TableSearch
            value={searchValue}
            onChange={onSearchChange}
            placeholder={searchPlaceholder}
          />

          <FilterToggle
            isOpen={showFilter}
            onToggle={onFilterToggle}
            activeFiltersCount={activeFiltersCount}
            isLoading={filterLoading}
          />

          <ColumnVisibility
            toggleableColumns={toggleableColumns}
            visibleCount={visibleCount}
            totalCount={totalCount}
            columnConfigs={columnConfigs}
            onShowAll={onShowAllColumns}
            onHideAll={onHideAllColumns}
            onReset={onResetColumns}
          />

          <Button variant="outline" onClick={onRefresh} disabled={isRefreshing}>
            <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin' : ''}`} />
          </Button>
        </div>

        {showFilter && children && (
          <div className="border border-muted rounded-lg bg-muted/90 px-4 py-3 mt-6">
            {children}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

