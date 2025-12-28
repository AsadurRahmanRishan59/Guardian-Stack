// 5. Table Pagination Component
// components/table/TablePagination.tsx
import React from "react";
import {
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { PaginationInfo } from "@/lib/hooks/useDataTable";

interface TablePaginationProps {
  pagination: PaginationInfo;
  onPageChange: (page: number) => void;
}

export const TablePagination: React.FC<TablePaginationProps> = ({
  pagination,
  onPageChange,
}) => {
  return (
    <div className="flex items-center justify-between px-6 py-4">
      <div className="text-sm text-muted-foreground">
        Showing {pagination.currentPage * pagination.pageSize + 1} to{" "}
        {Math.min(
          (pagination.currentPage + 1) * pagination.pageSize,
          pagination.totalElements
        )}{" "}
        of {pagination.totalElements} results
      </div>

      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => onPageChange(0)}
            disabled={!pagination.hasPrevious}
          >
            <ChevronsLeft className="h-4 w-4" />
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => onPageChange(pagination.currentPage - 1)}
            disabled={!pagination.hasPrevious}
          >
            <ChevronLeft className="h-4 w-4" />
          </Button>

          <div className="text-sm font-medium">
            Page {pagination.currentPage + 1} of {pagination.totalPages}
          </div>

          <Button
            variant="outline"
            size="sm"
            onClick={() => onPageChange(pagination.currentPage + 1)}
            disabled={!pagination.hasNext}
          >
            <ChevronRight className="h-4 w-4" />
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => onPageChange(pagination.totalPages - 1)}
            disabled={!pagination.hasNext}
          >
            <ChevronsRight className="h-4 w-4" />
          </Button>
        </div>
      </div>
    </div>
  );
};
