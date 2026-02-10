package com.rishan.guardianstack.auth.dto.response;

import lombok.Builder;

import java.time.LocalDateTime;

/**
 * DTO for Role Change History
 *
 * Represents a single role assignment or removal event
 * from the gs_user_roles_aud table
 */
@Builder
public record RoleChangeHistoryDTO(
        /**
         * Revision number (unique identifier for this change)
         */
        Long revisionNumber,

        /**
         * Type of change:
         * - ADD (0) = Role was assigned to user
         * - DEL (2) = Role was removed from user
         */
        String revisionType,

        /**
         * When the change was made
         */
        LocalDateTime timestamp,

        /**
         * Who made the change (username from Spring Security)
         */
        String changedBy,

        /**
         * IP address from where the change was made
         */
        String ipAddress,

        // =========================================================================
        // ROLE CHANGE DETAILS
        // =========================================================================

        /**
         * User ID who received/lost the role
         */
        Long userId,

        /**
         * User email (for display)
         */
        String userEmail,

        /**
         * Username (for display)
         */
        String username,

        /**
         * Role ID
         */
        Integer roleId,

        /**
         * Role name (e.g., "ROLE_ADMIN", "ROLE_USER")
         */
        String roleName
) {
    /**
     * Helper method to check if this was a role assignment
     */
    public boolean isRoleAssignment() {
        return "ADD".equals(revisionType);
    }

    /**
     * Helper method to check if this was a role removal
     */
    public boolean isRoleRemoval() {
        return "DEL".equals(revisionType);
    }
}