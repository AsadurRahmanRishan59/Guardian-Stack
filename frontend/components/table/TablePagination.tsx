// components/table/TablePagination.tsx
import React from 'react';
import {
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { PaginationInfo } from '@/lib/hooks/useDataTable';

interface TablePaginationProps {
  pagination: PaginationInfo;
  onPageChange: (page: number) => void;
}

export const TablePagination: React.FC<TablePaginationProps> = ({
  pagination,
  onPageChange,
}) => {
  const from = pagination.totalElements === 0
    ? 0
    : pagination.currentPage * pagination.pageSize + 1;
  const to = Math.min(
    (pagination.currentPage + 1) * pagination.pageSize,
    pagination.totalElements
  );

  return (
    <div className="flex flex-col sm:flex-row items-center justify-between gap-3 px-4 sm:px-6 py-4 border-t border-gs-line">
      {/* Result range */}
      <p className="text-xs text-t3 order-2 sm:order-1">
        {pagination.totalElements === 0
          ? 'No results'
          : <>Showing <span className="font-medium text-t2">{from}–{to}</span> of <span className="font-medium text-t2">{pagination.totalElements}</span></>
        }
      </p>

      {/* Navigation */}
      <div className="flex items-center gap-1 order-1 sm:order-2">
        <Button
          variant="outline"
          size="icon"
          className="h-8 w-8 border-gs-line text-t3 hover:text-t1 hover:bg-surface-2 disabled:opacity-40"
          onClick={() => onPageChange(0)}
          disabled={!pagination.hasPrevious}
          aria-label="First page"
        >
          <ChevronsLeft className="h-3.5 w-3.5" />
        </Button>
        <Button
          variant="outline"
          size="icon"
          className="h-8 w-8 border-gs-line text-t3 hover:text-t1 hover:bg-surface-2 disabled:opacity-40"
          onClick={() => onPageChange(pagination.currentPage - 1)}
          disabled={!pagination.hasPrevious}
          aria-label="Previous page"
        >
          <ChevronLeft className="h-3.5 w-3.5" />
        </Button>

        <div className="flex items-center gap-1 px-3 h-8 rounded-gs border border-gs-line bg-surface text-xs font-medium text-t2 select-none">
          <span className="text-brand font-semibold">{pagination.currentPage + 1}</span>
          <span className="text-t4">/</span>
          <span>{pagination.totalPages || 1}</span>
        </div>

        <Button
          variant="outline"
          size="icon"
          className="h-8 w-8 border-gs-line text-t3 hover:text-t1 hover:bg-surface-2 disabled:opacity-40"
          onClick={() => onPageChange(pagination.currentPage + 1)}
          disabled={!pagination.hasNext}
          aria-label="Next page"
        >
          <ChevronRight className="h-3.5 w-3.5" />
        </Button>
        <Button
          variant="outline"
          size="icon"
          className="h-8 w-8 border-gs-line text-t3 hover:text-t1 hover:bg-surface-2 disabled:opacity-40"
          onClick={() => onPageChange(pagination.totalPages - 1)}
          disabled={!pagination.hasNext}
          aria-label="Last page"
        >
          <ChevronsRight className="h-3.5 w-3.5" />
        </Button>
      </div>
    </div>
  );
};