// 3. Column Visibility Component
// components/table/ColumnVisibility.tsx
import React from 'react';
import { ArrowUpDown, Columns, Eye, EyeOff } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { TableColumnConfig } from '@/hooks/useDataTable';
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
        <Button variant="outline" className="relative">
          <Columns className="mr-2 h-4 w-4" />
          Columns
          <Badge variant="default" className="ml-2 px-1.5 py-0.5 text-[10px] rounded-full">
            {visibleCount}
          </Badge>
        </Button>
      </DropdownMenuTrigger>

      <DropdownMenuContent align="end" className="w-56">
        <div className="flex items-center justify-between px-2 py-1.5 text-sm font-medium">
          <span>Toggle Columns</span>
          <span className="text-xs text-muted-foreground">
            {visibleCount}/{totalCount}
          </span>
        </div>

        <div className="flex gap-1 px-2 py-1">
          <Button variant="ghost" size="sm" className="h-7 px-2 text-xs" onClick={onShowAll}>
            <Eye className="w-3 h-3 mr-1" />
            All
          </Button>
          <Button variant="ghost" size="sm" className="h-7 px-2 text-xs" onClick={onHideAll}>
            <EyeOff className="w-3 h-3 mr-1" />
            None
          </Button>
          <Button variant="ghost" size="sm" className="h-7 px-2 text-xs" onClick={onReset}>
            Reset
          </Button>
        </div>

        <div className="my-1 border-t border-muted" />

        {toggleableColumns.map((column) => {
          const config = columnConfigs.find((c) => c.key === column.id);
          return (
            <DropdownMenuCheckboxItem
              key={column.id}
              checked={column.getIsVisible()}
              onCheckedChange={(val) => column.toggleVisibility(!!val)}
              className="capitalize flex items-center justify-between"
            >
              <span>{config?.label ?? column.id}</span>
              {config?.sortable && (
                <ArrowUpDown className="ml-2 h-3 w-3 text-muted-foreground" />
              )}
            </DropdownMenuCheckboxItem>
          );
        })}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
