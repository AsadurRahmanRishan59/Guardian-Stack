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

function MobileCardRow<T>({ row, index }: { row: Row<T>; index: number }) {
  const cells = row.getVisibleCells();
  const isEven = index % 2 === 0;

  const indexCell = cells.find((c) => c.column.id === "index");
  const actionsCell = cells.find((c) => c.column.id === "actions");
  const bodyCells = cells.filter(
    (c) => c.column.id !== "index" && c.column.id !== "actions"
  );

  return (
    <div
      className={`rounded-gs border border-gs-line p-3 space-y-2.5 animate-fade-up ${
        isEven ? "bg-surface-card" : "bg-surface-2/40"
      }`}
    >
      {/* Card header: index badge + actions */}
      <div className="flex items-center justify-between">
        <span className="inline-flex items-center justify-center h-5 min-w-5 px-1.5 rounded bg-brand/10 text-brand text-[10px] font-bold tabular-nums">
          {indexCell
            ? flexRender(indexCell.column.columnDef.cell, indexCell.getContext())
            : null}
        </span>
        {actionsCell && (
          <div className="-mr-1.5">
            {flexRender(actionsCell.column.columnDef.cell, actionsCell.getContext())}
          </div>
        )}
      </div>

      {/* Field grid */}
      <dl className="grid grid-cols-2 gap-x-3 gap-y-2">
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
              <dt className="text-[9px] font-bold uppercase tracking-widest text-t4 truncate">
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
      <CardHeader className="px-3 sm:px-4 py-2.5 border-b border-gs-line bg-surface-2/50">
        <div className="flex items-center justify-between gap-2 flex-wrap">
          <CardTitle className="text-sm font-semibold text-t1 flex items-center gap-2 font-head">
            {title}
            <span className="inline-flex items-center justify-center h-5 min-w-5 px-1.5 rounded-full bg-brand text-white text-[10px] font-bold tabular-nums leading-none">
              {pagination.totalElements}
            </span>
            {isLoading && <Loader2 className="w-3.5 h-3.5 animate-spin text-brand" />}
          </CardTitle>

          <div className="flex items-center gap-1.5">
            <span className="text-xs text-t4 hidden sm:inline">Rows</span>
            <Select
              value={String(pagination.pageSize)}
              onValueChange={(val) => onPageSizeChange(Number(val))}
            >
              <SelectTrigger className="h-7 w-14 text-xs border-gs-line bg-surface text-t2 focus:ring-brand px-2">
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
            Slim styled scrollbar via inline styles
        ══════════════════════════════════════════════ */}
        <div
          className="hidden md:block overflow-x-auto"
          style={{
            scrollbarWidth: "thin",
            scrollbarColor: "var(--gs-line-2) transparent",
          }}
        >
          <Table>
            <TableHeader>
              {table.getHeaderGroups().map((headerGroup: HeaderGroup<T>) => (
                <TableRow
                  key={headerGroup.id}
                  className="border-b border-gs-line hover:bg-transparent"
                >
                  {headerGroup.headers.map((header: Header<T, unknown>, colIdx) => (
                    <TableHead
                      key={header.id}
                      className={`h-8 px-3 text-[10px] font-bold uppercase tracking-wider whitespace-nowrap ${
                        colIdx === 0
                          ? "bg-brand/8 text-brand w-10 text-center"
                          : "bg-surface-2 text-t4"
                      }`}
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
                  <TableCell colSpan={columns.length} className="py-10 text-center">
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
                      <TableCell key={colIndex} className="py-2 px-3">
                        <Skeleton className="h-3.5 w-full bg-surface-3" />
                      </TableCell>
                    ))}
                  </TableRow>
                ))
              ) : table.getRowModel().rows.length ? (
                table.getRowModel().rows.map((row: Row<T>, rowIdx) => (
                  <TableRow
                    key={row.id}
                    className={`border-b border-gs-line transition-colors ${
                      rowIdx % 2 === 0
                        ? "bg-surface-card hover:bg-brand/5"
                        : "bg-surface-2/35 hover:bg-brand/5"
                    }`}
                  >
                    {row.getVisibleCells().map((cell: Cell<T, unknown>, cellIdx) => (
                      <TableCell
                        key={cell.id}
                        className={`py-2 px-3 text-sm ${
                          cellIdx === 0
                            ? "text-center font-bold text-brand/70 bg-brand/5 w-10"
                            : "text-t1"
                        }`}
                      >
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
                    className="text-center py-10 text-sm text-t4"
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
        <div className="md:hidden p-2 space-y-1.5">
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
                className="rounded-gs border border-gs-line bg-surface-card p-3 space-y-2"
              >
                <div className="flex justify-between">
                  <Skeleton className="h-4 w-8 bg-surface-3 rounded" />
                  <Skeleton className="h-6 w-7 bg-surface-3 rounded-gs-sm" />
                </div>
                <div className="grid grid-cols-2 gap-2">
                  {Array.from({ length: 4 }).map((_, j) => (
                    <div key={j} className="space-y-1">
                      <Skeleton className="h-2 w-10 bg-surface-3" />
                      <Skeleton className="h-3.5 w-20 bg-surface-3" />
                    </div>
                  ))}
                </div>
              </div>
            ))
          ) : table.getRowModel().rows.length ? (
            table.getRowModel().rows.map((row: Row<T>, rowIdx) => (
              <MobileCardRow key={row.id} row={row} index={rowIdx} />
            ))
          ) : (
            <div className="text-center py-10 text-sm text-t4">{emptyMessage}</div>
          )}
        </div>
      </CardContent>

      {/* ── Pagination ── */}
      <TablePagination pagination={pagination} onPageChange={onPageChange} />
    </Card>
  );
}