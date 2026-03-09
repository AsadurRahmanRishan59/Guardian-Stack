// components/table/ColumnVisibility.tsx
import React from 'react';
import { Columns3, Eye, EyeOff, RotateCcw } from 'lucide-react';
import { Button } from '@/components/ui/button';
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { TableColumnConfig } from '@/lib/generateColumns';
import { Column } from '@tanstack/react-table';

interface ColumnVisibilityProps<T> {
  toggleableColumns: Column<T, unknown>[];
  visibleCount: number;
  totalCount: number;
  columnConfigs: TableColumnConfig<T>[];
  onShowAll: () => void;
  onHideAll: () => void;
  onReset: () => void;
}

export function ColumnVisibility<T>({
  toggleableColumns,
  visibleCount,
  totalCount,
  columnConfigs,
  onShowAll,
  onHideAll,
  onReset,
}: ColumnVisibilityProps<T>) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="outline"
          className="relative h-9 gap-2 border-gs-line text-t2 hover:text-t1 hover:bg-surface-2 hover:border-gs-line-2 transition-colors"
        >
          <Columns3 className="h-4 w-4" />
          <span className="hidden sm:inline">Columns</span>
          <span className="flex items-center justify-center h-4 w-4 rounded-full bg-surface-3 text-t3 text-[10px] font-semibold leading-none">
            {visibleCount}
          </span>
        </Button>
      </DropdownMenuTrigger>

      <DropdownMenuContent align="end" className="w-52 bg-surface-card border-gs-line shadow-lg">
        {/* Header */}
        <div className="flex items-center justify-between px-3 py-2">
          <span className="text-xs font-semibold text-t2 uppercase tracking-wide">Columns</span>
          <span className="text-xs text-t4">{visibleCount} / {totalCount}</span>
        </div>

        {/* Quick actions */}
        <div className="flex gap-1 px-2 pb-2">
          <Button
            variant="ghost"
            size="sm"
            className="h-7 px-2 text-xs text-t3 hover:text-t1 hover:bg-surface-2 flex-1 gap-1"
            onClick={onShowAll}
          >
            <Eye className="w-3 h-3" /> All
          </Button>
          <Button
            variant="ghost"
            size="sm"
            className="h-7 px-2 text-xs text-t3 hover:text-t1 hover:bg-surface-2 flex-1 gap-1"
            onClick={onHideAll}
          >
            <EyeOff className="w-3 h-3" /> None
          </Button>
          <Button
            variant="ghost"
            size="sm"
            className="h-7 px-2 text-xs text-t3 hover:text-t1 hover:bg-surface-2 flex-1 gap-1"
            onClick={onReset}
          >
            <RotateCcw className="w-3 h-3" /> Reset
          </Button>
        </div>

        <DropdownMenuSeparator className="bg-gs-line" />

        {toggleableColumns.map((column) => {
          const config = columnConfigs.find((c) => c.key === column.id);
          return (
            <DropdownMenuCheckboxItem
              key={column.id}
              checked={column.getIsVisible()}
              onCheckedChange={(val) => column.toggleVisibility(!!val)}
              className="text-sm text-t2 focus:bg-surface-2 focus:text-t1 cursor-pointer"
            >
              {config?.label ?? column.id}
            </DropdownMenuCheckboxItem>
          );
        })}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}