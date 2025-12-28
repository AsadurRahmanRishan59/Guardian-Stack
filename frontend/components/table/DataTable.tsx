// 7. Generic Data Table Component
// components/table/DataTable.tsx
import React from "react";
import {
  Table as TanStackTable,
  Cell,
  ColumnDef,
  flexRender,
  Header,
  HeaderGroup,
  Row,
} from "@tanstack/react-table";
import { AlertTriangle, Loader2 } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { PaginationInfo } from "@/lib/hooks/useDataTable";
import { TablePagination } from "./TablePagination";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "../ui/select";

interface DataTableProps<T> {
  table: TanStackTable<T>; // ReactTable instance
  columns: ColumnDef<T>[];
  data: T[];
  pagination: PaginationInfo;
  isLoading?: boolean;
  error?: Error | null;
  onRefresh?: () => void;
  onPageChange: (page: number) => void;
  onPageSizeChange: (size: number) => void;
  title?: string;
  emptyMessage?: string;
}

export function DataTable<T>({
  table,
  columns,
  // data,
  pagination,
  isLoading,
  error,
  onRefresh,
  onPageChange,
  onPageSizeChange,
  title,
  emptyMessage = "No data found.",
}: DataTableProps<T>) {
  const pageSizeOptions = [10, 20, 30, 50];
  return (
    <Card className="px-4">
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="text-base font-medium flex items-center gap-2">
            {title} ({pagination.totalElements})
            {isLoading && <Loader2 className="w-4 h-4 animate-spin" />}
          </CardTitle>

          <div className="flex items-center gap-2">
            <span className="text-sm text-muted-foreground">
              Rows per page:
            </span>
            <Select
              value={String(pagination.pageSize)}
              onValueChange={(val) => onPageSizeChange(Number(val))}
            >
              <SelectTrigger className="w-20">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {pageSizeOptions.map((size) => (
                  <SelectItem key={size} value={String(size)}>
                    {size}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>
      </CardHeader>

      <CardContent className="p-0">
        <Table>
          <TableHeader>
            {table.getHeaderGroups().map((headerGroup: HeaderGroup<T>) => (
              <TableRow key={headerGroup.id}>
                {headerGroup.headers.map((header: Header<T, unknown>) => (
                  <TableHead key={header.id} className="text-xs uppercase">
                    {flexRender(
                      header.column.columnDef.header,
                      header.getContext()
                    )}
                  </TableHead>
                ))}
              </TableRow>
            ))}
          </TableHeader>

          <TableBody>
            {error ? (
              <TableRow>
                <TableCell
                  colSpan={columns.length}
                  className="py-8 text-center"
                >
                  <div className="flex flex-col items-center justify-center gap-2 text-sm text-destructive">
                    <AlertTriangle className="w-5 h-5" />
                    <span>{error.message || "Failed to load data."}</span>
                    {onRefresh && (
                      <Button variant="outline" size="sm" onClick={onRefresh}>
                        Retry
                      </Button>
                    )}
                  </div>
                </TableCell>
              </TableRow>
            ) : isLoading ? (
              Array.from({ length: 5 }).map((_, index) => (
                <TableRow key={index}>
                  {columns.map((_, colIndex) => (
                    <TableCell key={colIndex} className="py-2">
                      <Skeleton className="h-4 w-full" />
                    </TableCell>
                  ))}
                </TableRow>
              ))
            ) : table.getRowModel().rows.length ? (
              table.getRowModel().rows.map((row: Row<T>) => (
                <TableRow key={row.id} className="hover:bg-muted/50">
                  {row.getVisibleCells().map((cell: Cell<T, unknown>) => (
                    <TableCell key={cell.id} className="py-2">
                      {flexRender(
                        cell.column.columnDef.cell,
                        cell.getContext()
                      )}
                    </TableCell>
                  ))}
                </TableRow>
              ))
            ) : (
              <TableRow>
                <TableCell
                  colSpan={columns.length}
                  className="text-center py-8"
                >
                  {emptyMessage}
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </CardContent>

      <TablePagination
        pagination={pagination}
        onPageChange={onPageChange}
      />
    </Card>
  );
}
