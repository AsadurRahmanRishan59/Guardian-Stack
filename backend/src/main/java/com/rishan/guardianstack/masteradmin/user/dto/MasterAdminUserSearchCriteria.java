package com.rishan.guardianstack.masteradmin.user.dto;

import com.rishan.guardianstack.auth.model.SignUpMethod;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Pattern;

import java.util.List;

public record MasterAdminUserSearchCriteria(
        // Search
        @Pattern(
                regexp = "^[a-zA-Z\\s.]+$",
                message = "Name can only contain letters, spaces, and dots (e.g., Md. Karim)"
        )
        String username,
        @Email(message = "Invalid email format")
        String email,

        // Filter
        Boolean accountLocked,
        Boolean accountNonExpired,
        Boolean enabled,
        SignUpMethod signUpMethod,
        List<Integer> roleIds,

        // Pagination
        @Min(value = 0, message = "Page number must be non-negative") Integer page,

        @Min(value = 1, message = "Page size must be at least 1") Integer size,

        // Sorting
        @Pattern(regexp = "^(userId|username|createdAt|updatedAt)$", message = "Sort field must be one of: User ID, User Name, Created Date, Updated Date") String sortBy,

        @Pattern(regexp = "^(asc|desc)$", message = "Sort direction must be 'asc' or 'desc'") String sortDirection
) {
    // ✅ Default values for pagination and sorting
    public static final int DEFAULT_PAGE = 0;
    public static final int DEFAULT_SIZE = 10;
    public static final String DEFAULT_SORT_BY = "agentName";
    public static final String DEFAULT_SORT_DIRECTION = "asc";

    // ✅ Default initializer logic
    public MasterAdminUserSearchCriteria {
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
