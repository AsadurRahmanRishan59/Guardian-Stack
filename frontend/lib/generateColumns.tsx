// lib/generateColumns.tsx
import { ColumnDef } from "@tanstack/react-table";
import {
  ArrowDown,
  ArrowUp,
  ArrowUpDown,
  Eye,
  MoreVertical,
  Pencil,
  Trash,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Button } from "@/components/ui/button";
import { useState } from "react";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { cn } from "@/lib/utils";

export type TableColumnConfig<T> = {
  key: keyof T & string;
  label: string;
  visible?: boolean;
  sortable?: boolean;
  isDate?: boolean;
  isBoolean?: boolean;
  isNegative?: boolean;
  trueLabel?: string;
  falseLabel?: string;
};

export function generateColumns<T>(
  config: TableColumnConfig<T>[]
): ColumnDef<T>[] {
  return config.map((col) => {
    const common: ColumnDef<T> = {
      accessorKey: col.key,
      header: ({ column }) => {
        if (!col.sortable)
          return (
            <span className="text-[10px] font-semibold uppercase tracking-wide text-t4">
              {col.label}
            </span>
          );
        const isSorted = column.getIsSorted();
        return (
          <button
            className="flex items-center gap-1 cursor-pointer select-none group text-[10px] font-semibold uppercase tracking-wide text-t4 hover:text-t2 transition-colors"
            onClick={column.getToggleSortingHandler()}
          >
            {col.label}
            {isSorted === "asc" && (
              <ArrowUp className="w-3 h-3 text-brand" />
            )}
            {isSorted === "desc" && (
              <ArrowDown className="w-3 h-3 text-brand" />
            )}
            {!isSorted && (
              <ArrowUpDown className="w-3 h-3 opacity-0 group-hover:opacity-100 transition-opacity" />
            )}
          </button>
        );
      },
      enableSorting: col.sortable,
    };

    // 1. Boolean badge
    if (col.isBoolean) {
      return {
        ...common,
        cell: ({ row }) => {
          const value = row.getValue(col.key) as boolean;
          const isGood = col.isNegative ? !value : value;

          return (
            <Badge
              variant={isGood ? "default" : "destructive"}
              className={cn(
                "text-[10px] font-semibold px-2 py-0.5 w-20 justify-center rounded-full",
                isGood
                  ? "bg-gs-green-bg text-gs-green border-transparent"
                  : "bg-destructive/10 text-destructive border-transparent"
              )}
            >
              {value
                ? col.trueLabel || "Yes"
                : col.falseLabel || "No"}
            </Badge>
          );
        },
      };
    }

    // 2. Date
    if (col.isDate) {
      return {
        ...common,
        cell: ({ row }) => {
          const raw = row.original[col.key] as
            | string
            | number
            | Date
            | undefined;
          const date = raw ? new Date(raw) : null;
          return date && !isNaN(date.getTime()) ? (
            <span className="text-sm text-t2 tabular-nums">
              {date.toLocaleDateString("en-GB")}
            </span>
          ) : (
            <span className="text-t4">—</span>
          );
        },
      };
    }

    // 3. Default text
    return {
      ...common,
      cell: ({ row }) => {
        const value = row.original[col.key];
        return (
          <span className="text-sm text-t1 whitespace-normal break-words">
            {String(value ?? "")}
          </span>
        );
      },
    };
  });
}

// ── Index column ───────────────────────────────────────────────────────────────

export function createIndexColumn<T>(): ColumnDef<T> {
  return {
    id: "index",
    header: () => (
      <span className="text-[10px] font-semibold uppercase tracking-wide text-t4">
        #
      </span>
    ),
    enableSorting: false,
    enableHiding: false,
    cell: ({ row, table }) => {
      const pageIndex = table.getState().pagination?.pageIndex ?? 0;
      const pageSize = table.getState().pagination?.pageSize ?? 10;
      return (
        <span className="text-sm text-t4 tabular-nums font-medium">
          {pageIndex * pageSize + row.index + 1}
        </span>
      );
    },
  };
}

// ── Actions column ─────────────────────────────────────────────────────────────

export function createActionsColumn<T>(
  onView: (id: string | number) => void,
  onDelete?: (id: string | number) => void,
  onEdit?: (id: string | number) => void,
  entityName?: string
): ColumnDef<T> {
  return {
    id: "actions",
    header: () => (
      <span className="text-[10px] font-semibold uppercase tracking-wide text-t4">
        Actions
      </span>
    ),
    enableHiding: false,
    cell: ({ row }) => (
      <ActionsCell
        row={row}
        onView={onView}
        onDelete={onDelete}
        onEdit={onEdit}
        entityName={entityName}
      />
    ),
  };
}

type ActionsCellProps<T extends { id: string | number }> = {
  row: T;
  onView: (id: string | number) => void;
  onDelete?: (id: string | number) => void;
  onEdit?: (id: string | number) => void;
  entityName?: string;
};

function ActionsCell<T extends { id: string | number }>({
  row,
  onView,
  onDelete,
  onEdit,
  entityName = "item",
}: ActionsCellProps<T>) {
  const id = row.id;
  const [confirmOpen, setConfirmOpen] = useState(false);

  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button
            variant="ghost"
            className="h-8 w-8 p-0 text-t3 hover:text-t1 hover:bg-surface-2 transition-colors"
            aria-label={`Actions for ${id}`}
          >
            <MoreVertical className="h-4 w-4" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent
          align="end"
          className="bg-surface-card border-gs-line shadow-lg w-40"
        >
          <DropdownMenuItem
            onClick={() => onView(id)}
            className="text-sm text-t2 focus:bg-surface-2 focus:text-t1 cursor-pointer gap-2"
          >
            <Eye className="h-3.5 w-3.5" />
            View
          </DropdownMenuItem>
          {onEdit && (
            <DropdownMenuItem
              onClick={() => onEdit(id)}
              className="text-sm text-t2 focus:bg-surface-2 focus:text-t1 cursor-pointer gap-2"
            >
              <Pencil className="h-3.5 w-3.5" />
              Edit
            </DropdownMenuItem>
          )}

          {onDelete && (
            <>
              <DropdownMenuSeparator className="bg-gs-line" />
              <DropdownMenuItem
                onClick={() => setConfirmOpen(true)}
                className="text-sm text-destructive focus:bg-destructive/10 focus:text-destructive cursor-pointer gap-2"
              >
                <Trash className="h-3.5 w-3.5" />
                Delete
              </DropdownMenuItem>
            </>
          )}
        </DropdownMenuContent>
      </DropdownMenu>

      {onDelete && (
        <ConfirmDialog
          open={confirmOpen}
          onOpenChange={setConfirmOpen}
          onConfirm={() => {
            onDelete(id);
            setConfirmOpen(false);
          }}
          title={`Delete ${entityName}?`}
          description={`This action cannot be undone. This will permanently delete the ${entityName}.`}
          confirmText="Delete"
          cancelText="Cancel"
        />
      )}
    </>
  );
}