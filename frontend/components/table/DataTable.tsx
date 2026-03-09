// components/table/DataTable.tsx
"use client";

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
  table: TanStackTable<T>;
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

// ─── Mobile card row ──────────────────────────────────────────────────────────

function MobileCardRow<T>({ row }: { row: Row<T> }) {
  const cells = row.getVisibleCells();

  // Split: index + actions are pinned; rest are body cells
  const indexCell = cells.find((c) => c.column.id === "index");
  const actionsCell = cells.find((c) => c.column.id === "actions");
  const bodyCells = cells.filter(
    (c) => c.column.id !== "index" && c.column.id !== "actions"
  );

  return (
    <div className="rounded-gs border border-gs-line bg-surface-card p-4 space-y-3 animate-fade-up">
      {/* Card header: index + actions */}
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold text-t4 tabular-nums">
          {indexCell
            ? flexRender(indexCell.column.columnDef.cell, indexCell.getContext())
            : null}
        </span>
        {actionsCell && (
          <div className="-mr-2">
            {flexRender(actionsCell.column.columnDef.cell, actionsCell.getContext())}
          </div>
        )}
      </div>

      {/* Field grid */}
      <dl className="grid grid-cols-2 gap-x-4 gap-y-2.5">
        {bodyCells.map((cell: Cell<T, unknown>) => {
          const headerDef = cell.column.columnDef.header;
          const headerLabel =
            typeof headerDef === "string"
              ? headerDef
              : cell.column.id
                  .replace(/([A-Z])/g, " $1")
                  .replace(/^./, (s) => s.toUpperCase());

          return (
            <div key={cell.id} className="space-y-0.5 min-w-0">
              <dt className="text-[10px] font-semibold uppercase tracking-wide text-t4 truncate">
                {headerLabel}
              </dt>
              <dd className="text-sm text-t1 truncate">
                {flexRender(cell.column.columnDef.cell, cell.getContext())}
              </dd>
            </div>
          );
        })}
      </dl>
    </div>
  );
}

// ─── Main DataTable ───────────────────────────────────────────────────────────

export function DataTable<T>({
  table,
  columns,
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

  const skeletonRows = Array.from({ length: 5 });

  return (
    <Card className="border-gs-line bg-surface-card shadow-none overflow-hidden">
      {/* ── Header ── */}
      <CardHeader className="px-4 sm:px-6 py-4 border-b border-gs-line">
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <CardTitle className="text-sm font-semibold text-t1 flex items-center gap-2 font-head">
            {title}
            <span className="text-xs font-normal text-t4 bg-surface-2 px-2 py-0.5 rounded-full border border-gs-line">
              {pagination.totalElements}
            </span>
            {isLoading && <Loader2 className="w-3.5 h-3.5 animate-spin text-brand" />}
          </CardTitle>

          <div className="flex items-center gap-2">
            <span className="text-xs text-t4 hidden sm:inline">Rows per page</span>
            <Select
              value={String(pagination.pageSize)}
              onValueChange={(val) => onPageSizeChange(Number(val))}
            >
              <SelectTrigger className="h-8 w-16 text-xs border-gs-line bg-surface text-t2 focus:ring-brand">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="bg-surface-card border-gs-line">
                {pageSizeOptions.map((size) => (
                  <SelectItem
                    key={size}
                    value={String(size)}
                    className="text-xs text-t2 focus:bg-surface-2 focus:text-t1"
                  >
                    {size}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>
      </CardHeader>

      <CardContent className="p-0">
        {/* ══════════════════════════════════════════════
            DESKTOP — standard table (md and up)
        ══════════════════════════════════════════════ */}
        <div className="hidden md:block overflow-x-auto">
          <Table>
            <TableHeader>
              {table.getHeaderGroups().map((headerGroup: HeaderGroup<T>) => (
                <TableRow
                  key={headerGroup.id}
                  className="border-b border-gs-line hover:bg-transparent"
                >
                  {headerGroup.headers.map((header: Header<T, unknown>) => (
                    <TableHead
                      key={header.id}
                      className="h-9 px-4 text-[10px] font-semibold uppercase tracking-wide text-t4 bg-surface-2"
                    >
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
                  <TableCell colSpan={columns.length} className="py-12 text-center">
                    <div className="flex flex-col items-center gap-2 text-sm text-destructive">
                      <AlertTriangle className="w-5 h-5" />
                      <span>{error.message || "Failed to load data."}</span>
                      {onRefresh && (
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={onRefresh}
                          className="mt-1 border-gs-line text-t2 hover:bg-surface-2"
                        >
                          Retry
                        </Button>
                      )}
                    </div>
                  </TableCell>
                </TableRow>
              ) : isLoading ? (
                skeletonRows.map((_, index) => (
                  <TableRow key={index} className="border-b border-gs-line">
                    {columns.map((_, colIndex) => (
                      <TableCell key={colIndex} className="py-2.5 px-4">
                        <Skeleton className="h-4 w-full bg-surface-3" />
                      </TableCell>
                    ))}
                  </TableRow>
                ))
              ) : table.getRowModel().rows.length ? (
                table.getRowModel().rows.map((row: Row<T>) => (
                  <TableRow
                    key={row.id}
                    className="border-b border-gs-line hover:bg-surface-2/60 transition-colors"
                  >
                    {row.getVisibleCells().map((cell: Cell<T, unknown>) => (
                      <TableCell key={cell.id} className="py-2.5 px-4 text-sm text-t1">
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
                    className="text-center py-12 text-sm text-t4"
                  >
                    {emptyMessage}
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </div>

        {/* ══════════════════════════════════════════════
            MOBILE — card layout (below md)
        ══════════════════════════════════════════════ */}
        <div className="md:hidden p-3 space-y-2">
          {error ? (
            <div className="flex flex-col items-center gap-2 py-10 text-sm text-destructive">
              <AlertTriangle className="w-5 h-5" />
              <span>{error.message || "Failed to load data."}</span>
              {onRefresh && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={onRefresh}
                  className="mt-1 border-gs-line text-t2 hover:bg-surface-2"
                >
                  Retry
                </Button>
              )}
            </div>
          ) : isLoading ? (
            skeletonRows.map((_, i) => (
              <div
                key={i}
                className="rounded-gs border border-gs-line bg-surface-card p-4 space-y-3"
              >
                <div className="flex justify-between">
                  <Skeleton className="h-3 w-6 bg-surface-3" />
                  <Skeleton className="h-7 w-8 bg-surface-3 rounded-gs-sm" />
                </div>
                <div className="grid grid-cols-2 gap-2">
                  {Array.from({ length: 4 }).map((_, j) => (
                    <div key={j} className="space-y-1">
                      <Skeleton className="h-2 w-12 bg-surface-3" />
                      <Skeleton className="h-4 w-24 bg-surface-3" />
                    </div>
                  ))}
                </div>
              </div>
            ))
          ) : table.getRowModel().rows.length ? (
            table.getRowModel().rows.map((row: Row<T>) => (
              <MobileCardRow key={row.id} row={row} />
            ))
          ) : (
            <div className="text-center py-12 text-sm text-t4">{emptyMessage}</div>
          )}
        </div>
      </CardContent>

      {/* ── Pagination ── */}
      <TablePagination pagination={pagination} onPageChange={onPageChange} />
    </Card>
  );
}