package com.rishan.guardianstack.tariff.motor.dto;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Pattern;

public record MotorTariffMasterAdminViewSearchCriteria(

        // Search
        @Min(value = 1, message = "Tariff Key must be a positive number") Integer tariffKey,

        // Filters
        String tariffType,
        String groupOfVehicle,
        String typeOfVehicle,
        String category,
        Boolean isActive,

        // Pagination
        @Min(value = 0, message = "Page number must be non-negative") Integer page,

        @Min(value = 1, message = "Page size must be at least 1") Integer size,

        // Sorting
        @Pattern(regexp = "^(tariffKey|tariffType|groupOfVehicle|typeOfVehicle|category)$", message = "Sort field must be one of: Tariff Key.Tariff Type, Group Of Vehicle, Type of Vehicle, Category") String sortBy,

        @Pattern(regexp = "^(asc|desc)$", message = "Sort direction must be 'asc' or 'desc'") String sortDirection

) {
    // ✅ Default values for pagination and sorting
    public static final int DEFAULT_PAGE = 0;
    public static final int DEFAULT_SIZE = 10;
    public static final String DEFAULT_SORT_BY = "tariffKey";
    public static final String DEFAULT_SORT_DIRECTION = "asc";

    // ✅ Default initializer logic
    public MotorTariffMasterAdminViewSearchCriteria {
        if (page == null)
            page = DEFAULT_PAGE;
        if (size == null)
            size = DEFAULT_SIZE;
        if (sortBy == null || sortBy.isBlank())
            sortBy = DEFAULT_SORT_BY;
        if (sortDirection == null || sortDirection.isBlank())
            sortDirection = DEFAULT_SORT_DIRECTION;
    }
}
