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

export type TableColumnConfig<T> = {
  key: keyof T;
  label: string;
  visible?: boolean;
  sortable?: boolean;
  isDate?: boolean;
};

export function generateColumns<T>(
  config: TableColumnConfig<T>[]
): ColumnDef<T>[] {
  return config.map((col) => {
    const common: ColumnDef<T> = {
      accessorKey: col.key,
      header: ({ column }) => {
        if (!col.sortable) return <span>{col.label}</span>;

        const isSorted = column.getIsSorted();

        return (
          <div
            className="flex items-center gap-1 cursor-pointer select-none"
            onClick={column.getToggleSortingHandler()}
          >
            <span>{col.label}</span>
            {isSorted === "asc" && <ArrowUp className="w-3 h-3" />}
            {isSorted === "desc" && <ArrowDown className="w-3 h-3" />}
            {isSorted === false && (
              <ArrowUpDown className="w-3 h-3 text-muted-foreground" />
            )}
          </div>
        );
      },
      enableSorting: col.sortable,
    };

    // Handle date formatting
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
          return date && !isNaN(date.getTime())
            ? date.toLocaleDateString("en-GB")
            : "";
        },
      };
    }

    // Default cell renderer with text wrapping
    return {
      ...common,
      cell: ({ row }) => {
        const value = row.original[col.key];
        return (
          <div className="whitespace-normal wrap-break-word text-sm ">
            {String(value ?? "")}
          </div>
        );
      },
    };
  });
}

export function createIndexColumn<T>(): ColumnDef<T> {
  return {
    id: "index",
    header: "#",
    enableSorting: false,
    enableHiding: false,
    cell: ({ row, table }) => {
      const pageIndex = table.getState().pagination?.pageIndex ?? 0;
      const pageSize = table.getState().pagination?.pageSize ?? 10;
      return pageIndex * pageSize + row.index + 1;
    },
  };
}

export function createIsActiveColumn<T extends { enabled: boolean }>(
  key: keyof T
): ColumnDef<T> {
  return {
    accessorKey: key,
    header: () => <div className="min-w-20 flex justify-center">Status</div>,
    cell: ({ row }) => {
      const value = row.original[key];
      return (
        <div className="min-w-20 flex justify-center">
          <Badge
            variant={value ? "default" : "destructive"}
            className="text-xs w-17.5 text-center"
          >
            {value ? "Active" : "Inactive"}
          </Badge>
        </div>
      );
    },
    enableSorting: false,
    enableHiding: true,
  };
}

export function createActionsColumn<T>(
  onView: (id: string | number) => void,
  onDelete?: (id: string | number) => void,
  onEdit?: (id: string | number) => void,
  entityName?: string
): ColumnDef<T> {
  return {
    id: "actions",
    header: "Actions",
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
  entityName?: string; // optional: e.g., "agent", "bank"
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
            className="h-8 w-8 p-0"
            aria-label={`Actions for ${id}`}
          >
            <MoreVertical className="h-4 w-4" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <DropdownMenuItem onClick={() => onView(id)}>
            <Eye className="mr-2 h-4 w-4" />
            View
          </DropdownMenuItem>
          {onEdit && (
            <DropdownMenuItem onClick={() => onEdit(id)}>
              <Pencil className="mr-2 h-4 w-4" />
              Edit
            </DropdownMenuItem>
          )}

          <DropdownMenuSeparator />

          {onDelete && (
            <DropdownMenuItem
              onClick={() => setConfirmOpen(true)}
              className="text-destructive focus:text-destructive"
            >
              <Trash className="mr-2 h-4 w-4" />
              Delete
            </DropdownMenuItem>
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
