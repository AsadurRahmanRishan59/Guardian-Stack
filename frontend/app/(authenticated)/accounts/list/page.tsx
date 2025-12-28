// app/vouchers/page.tsx
'use client';

import { useState, useMemo } from 'react';
import {
  useReactTable,
  getCoreRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  getFilteredRowModel,
  ColumnDef,
  flexRender,
  SortingState,
  ColumnFiltersState,
} from '@tanstack/react-table';
import { useVouchers, useDeleteVoucher, useDownloadPdf } from '@/lib/hooks/useVouchers';
import { AccountUserVoucherView } from '@/lib/api/voucher.service';
import { voucherService } from '@/lib/api/voucher.service';

export default function VouchersPage() {
  // Filters and pagination state
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(10);
  const [voucherType, setVoucherType] = useState('');
  const [voucherNumber, setVoucherNumber] = useState('');
  const [sorting, setSorting] = useState<SortingState>([
    { id: 'pdfUploadDate', desc: true }
  ]);
  const [columnFilters, setColumnFilters] = useState<ColumnFiltersState>([]);

  // Fetch vouchers using TanStack Query
  const { data, isLoading, isError, error } = useVouchers({
    page,
    size: pageSize,
    voucherType: voucherType || undefined,
    voucherNumber: voucherNumber || undefined,
    sortBy: sorting[0]?.id || 'pdfUploadDate',
    sortDirection: sorting[0]?.desc ? 'desc' : 'asc',
  });

  // Mutations
  const deleteMutation = useDeleteVoucher();
  const downloadMutation = useDownloadPdf();

  // Define columns
  const columns = useMemo<ColumnDef<AccountUserVoucherView>[]>(
    () => [
      {
        accessorKey: 'pdfId',
        header: 'ID',
        size: 80,
        enableSorting: true,
      },
      {
        accessorKey: 'voucherType',
        header: 'Type',
        size: 120,
        enableSorting: true,
        cell: ({ getValue }) => {
          const type = getValue<string>();
          const colors: Record<string, string> = {
            BP: 'bg-blue-100 text-blue-800',
            BR: 'bg-green-100 text-green-800',
            FT: 'bg-purple-100 text-purple-800',
            JV: 'bg-yellow-100 text-yellow-800',
            'JV(A)': 'bg-orange-100 text-orange-800',
          };
          return (
            <span className={`px-2 py-1 rounded text-sm font-medium ${colors[type] || 'bg-gray-100 text-gray-800'}`}>
              {type}
            </span>
          );
        },
      },
      {
        accessorKey: 'voucherCode',
        header: 'Code',
        size: 120,
        enableSorting: true,
      },
      {
        accessorKey: 'voucherNumber',
        header: 'Number',
        size: 120,
      },
      {
        accessorKey: 'pdfName',
        header: 'PDF Name',
        size: 300,
        cell: ({ getValue }) => (
          <span className="text-sm text-gray-900 truncate block" title={getValue<string>()}>
            {getValue<string>()}
          </span>
        ),
      },
      {
        accessorKey: 'voucherIssueDate',
        header: 'Issue Date',
        size: 140,
        enableSorting: true,
        cell: ({ getValue }) => {
          const date = getValue<string>();
          return date ? new Date(date).toLocaleDateString() : '-';
        },
      },
      {
        accessorKey: 'pdfUploadDate',
        header: 'Upload Date',
        size: 140,
        enableSorting: true,
        cell: ({ getValue }) => new Date(getValue<string>()).toLocaleDateString(),
      },
      {
        id: 'actions',
        header: 'Actions',
        size: 200,
        cell: ({ row }) => (
          <div className="flex gap-2">
            <button
              onClick={() => handleView(row.original.pdfId)}
              className="text-blue-600 hover:text-blue-800 text-sm font-medium"
            >
              View
            </button>
            <button
              onClick={() => handleDownload(row.original.pdfId, row.original.pdfName)}
              className="text-green-600 hover:text-green-800 text-sm font-medium"
              disabled={downloadMutation.isPending}
            >
              Download
            </button>
            <button
              onClick={() => handleDelete(row.original.pdfId)}
              className="text-red-600 hover:text-red-800 text-sm font-medium"
              disabled={deleteMutation.isPending}
            >
              Delete
            </button>
          </div>
        ),
      },
    ],
    [deleteMutation.isPending, downloadMutation.isPending]
  );

  // Initialize table
  const table = useReactTable({
    data: data?.content || [],
    columns,
    pageCount: data?.totalPages || 0,
    state: {
      sorting,
      columnFilters,
      pagination: {
        pageIndex: page,
        pageSize,
      },
    },
    onSortingChange: setSorting,
    onColumnFiltersChange: setColumnFilters,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    manualPagination: true,
    manualSorting: true,
  });

  // Handlers
  const handleView = (pdfId: number) => {
    const url = voucherService.getViewUrl(pdfId);
    window.open(url, '_blank');
  };

  const handleDownload = async (pdfId: number, filename: string) => {
    try {
      await downloadMutation.mutateAsync({ pdfId, filename });
    } catch (error: any) {
      alert('Failed to download: ' + error.message);
    }
  };

  const handleDelete = async (pdfId: number) => {
    if (!confirm('Are you sure you want to delete this voucher?')) return;

    try {
      await deleteMutation.mutateAsync(pdfId);
    } catch (error: any) {
      alert('Failed to delete: ' + error.message);
    }
  };

  const handlePageChange = (newPage: number) => {
    setPage(newPage);
  };

  return (
    <div className="container mx-auto p-6">
      <h1 className="text-3xl font-bold mb-6">Account Vouchers</h1>

      {/* Filters */}
      <div className="bg-white p-4 rounded-lg shadow mb-6">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label className="block text-sm font-medium mb-2">Voucher Type</label>
            <select
              value={voucherType}
              onChange={(e) => {
                setVoucherType(e.target.value);
                setPage(0);
              }}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="">All Types</option>
              <option value="BP">BP - Bank Payment</option>
              <option value="BR">BR - Bank Receipt</option>
              <option value="FT">FT - Fund Transfer</option>
              <option value="JV">JV - Journal Voucher</option>
              <option value="JV(A)">JV(A) - Journal Voucher Adjusted</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium mb-2">Voucher Number</label>
            <input
              type="text"
              value={voucherNumber}
              onChange={(e) => {
                setVoucherNumber(e.target.value);
                setPage(0);
              }}
              placeholder="Enter voucher number"
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>

          <div>
            <label className="block text-sm font-medium mb-2">Page Size</label>
            <select
              value={pageSize}
              onChange={(e) => {
                setPageSize(Number(e.target.value));
                setPage(0);
              }}
              className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value={5}>5</option>
              <option value={10}>10</option>
              <option value={20}>20</option>
              <option value={50}>50</option>
            </select>
          </div>
        </div>
      </div>

      {/* Error Message */}
      {isError && (
        <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
          {error?.message || 'Failed to load vouchers'}
        </div>
      )}

      {/* Loading State */}
      {isLoading ? (
        <div className="text-center py-8">
          <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-gray-900"></div>
          <p className="mt-2 text-gray-600">Loading vouchers...</p>
        </div>
      ) : (
        <>
          {/* Table */}
          <div className="bg-white rounded-lg shadow overflow-hidden">
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  {table.getHeaderGroups().map((headerGroup) => (
                    <tr key={headerGroup.id}>
                      {headerGroup.headers.map((header) => (
                        <th
                          key={header.id}
                          className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider"
                          style={{ width: header.getSize() }}
                        >
                          {header.isPlaceholder ? null : (
                            <div
                              className={
                                header.column.getCanSort()
                                  ? 'cursor-pointer select-none flex items-center gap-2'
                                  : ''
                              }
                              onClick={header.column.getToggleSortingHandler()}
                            >
                              {flexRender(header.column.columnDef.header, header.getContext())}
                              {{
                                asc: ' 🔼',
                                desc: ' 🔽',
                              }[header.column.getIsSorted() as string] ?? null}
                            </div>
                          )}
                        </th>
                      ))}
                    </tr>
                  ))}
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {table.getRowModel().rows.map((row) => (
                    <tr key={row.id} className="hover:bg-gray-50">
                      {row.getVisibleCells().map((cell) => (
                        <td key={cell.id} className="px-6 py-4 whitespace-nowrap text-sm">
                          {flexRender(cell.column.columnDef.cell, cell.getContext())}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Pagination */}
          <div className="mt-6 flex items-center justify-between">
            <div className="text-sm text-gray-700">
              Showing {data?.content.length || 0} of {data?.totalElements || 0} results
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => handlePageChange(0)}
                disabled={page === 0}
                className="px-3 py-1 bg-white border border-gray-300 rounded-md text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                First
              </button>
              <button
                onClick={() => handlePageChange(page - 1)}
                disabled={page === 0}
                className="px-3 py-1 bg-white border border-gray-300 rounded-md text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Previous
              </button>
              <span className="px-3 py-1 text-sm text-gray-700">
                Page {page + 1} of {data?.totalPages || 1}
              </span>
              <button
                onClick={() => handlePageChange(page + 1)}
                disabled={page >= (data?.totalPages || 1) - 1}
                className="px-3 py-1 bg-white border border-gray-300 rounded-md text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Next
              </button>
              <button
                onClick={() => handlePageChange((data?.totalPages || 1) - 1)}
                disabled={page >= (data?.totalPages || 1) - 1}
                className="px-3 py-1 bg-white border border-gray-300 rounded-md text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Last
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}