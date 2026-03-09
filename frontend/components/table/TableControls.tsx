// components/table/TableControls.tsx
import React from 'react';
import { RefreshCw } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent } from '@/components/ui/card';
import { cn } from '@/lib/utils';

import { TableSearch } from './TableSearch';
import { FilterToggle } from './FilterToggle';
import { ColumnVisibility } from './ColumnVisibility';
import { Column } from '@tanstack/react-table';
import { TableColumnConfig } from '@/lib/generateColumns';

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
  children?: React.ReactNode;
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
    <Card className="border-gs-line bg-surface-card shadow-none">
      <CardContent className="p-3 sm:p-4">
        {/* Controls row */}
        <div className="flex gap-2 items-center">
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

          <Button
            variant="outline"
            size="icon"
            onClick={onRefresh}
            disabled={isRefreshing}
            className="h-9 w-9 shrink-0 border-gs-line text-t3 hover:text-t1 hover:bg-surface-2 hover:border-gs-line-2 transition-colors"
            aria-label="Refresh"
          >
            <RefreshCw className={cn('h-4 w-4', isRefreshing && 'animate-spin')} />
          </Button>
        </div>

        {/* Filter panel — animated slide-down */}
        {showFilter && children && (
          <div className="mt-3 rounded-gs border border-gs-line bg-surface-2 px-4 py-3 animate-slide-down">
            {children}
          </div>
        )}
      </CardContent>
    </Card>
  );
}