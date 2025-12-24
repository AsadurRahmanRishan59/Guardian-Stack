package com.rishan.guardianstack.core.response;

import java.time.LocalDateTime;
import java.util.List;

public record PaginatedResponse<T>(
        boolean success,
        String message,
        List<T> data,
        PaginationInfo pagination,
        LocalDateTime timestamp) {

    public static class PaginationInfo {
        private final int currentPage;
        private final int pageSize;
        private final long totalElements;
        private final int totalPages;
        private final boolean hasNext;
        private final boolean hasPrevious;
        private final String sortBy;
        private final String sortDirection;

        public PaginationInfo(int currentPage, int pageSize, long totalElements, int totalPages,
                              boolean hasNext, boolean hasPrevious, String sortBy, String sortDirection) {
            this.currentPage = currentPage;
            this.pageSize = pageSize;
            this.totalElements = totalElements;
            this.totalPages = totalPages;
            this.hasNext = hasNext;
            this.hasPrevious = hasPrevious;
            this.sortBy = sortBy;
            this.sortDirection = sortDirection;
        }

        // Getters
        public int getCurrentPage() {
            return currentPage;
        }

        public int getPageSize() {
            return pageSize;
        }

        public long getTotalElements() {
            return totalElements;
        }

        public int getTotalPages() {
            return totalPages;
        }

        public boolean isHasNext() {
            return hasNext;
        }

        public boolean isHasPrevious() {
            return hasPrevious;
        }

        public String getSortBy() {
            return sortBy;
        }

        public String getSortDirection() {
            return sortDirection;
        }
    }

    // Static factory method for creating paginated responses
    public static <T> PaginatedResponse<T> of(List<T> data, int currentPage, int pageSize,
                                              long totalElements, int totalPages, boolean hasNext,
                                              boolean hasPrevious, String sortBy, String sortDirection,
                                              String message) {
        PaginationInfo paginationInfo = new PaginationInfo(
                currentPage, pageSize, totalElements, totalPages,
                hasNext, hasPrevious, sortBy, sortDirection);

        return new PaginatedResponse<>(
                true,
                message,
                data,
                paginationInfo,
                LocalDateTime.now());
    }
}