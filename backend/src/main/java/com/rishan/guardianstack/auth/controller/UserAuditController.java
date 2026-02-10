package com.rishan.guardianstack.auth.controller;

import com.rishan.guardianstack.auth.dto.response.RoleChangeHistoryDTO;
import com.rishan.guardianstack.masteradmin.audit.user.UserAuditHistoryDTO;
import com.rishan.guardianstack.auth.service.UserAuditService;
import lombok.RequiredArgsConstructor;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;

/**
 * REST Controller for User Audit History
 *
 * ✅ UPDATED: Added endpoints for role change tracking
 */
@RestController
@RequestMapping("/api/v1/admin/audit")
@RequiredArgsConstructor
public class UserAuditController {

    private final UserAuditService userAuditService;

    /**
     * Get complete audit history for a user
     *
     * GET /api/v1/admin/audit/users/123/history
     */
    @GetMapping("/users/{userId}/history")
    @PreAuthorize("hasAnyRole('ADMIN', 'MASTER_ADMIN')")
    public ResponseEntity<List<UserAuditHistoryDTO>> getUserAuditHistory(
            @PathVariable Long userId) {

        List<UserAuditHistoryDTO> history = userAuditService.getUserAuditHistory(userId);
        return ResponseEntity.ok(history);
    }

    /**
     * Get audit history within a date range
     *
     * GET /api/v1/admin/audit/users/123/history?from=2024-01-01T00:00:00&to=2024-12-31T23:59:59
     */
    @GetMapping("/users/{userId}/history/range")
    @PreAuthorize("hasAnyRole('ADMIN', 'MASTER_ADMIN')")
    public ResponseEntity<List<UserAuditHistoryDTO>> getUserAuditHistoryBetween(
            @PathVariable Long userId,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime from,
            @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime to) {

        List<UserAuditHistoryDTO> history = userAuditService.getUserAuditHistoryBetween(
                userId, from, to
        );
        return ResponseEntity.ok(history);
    }

    /**
     * Get email change history
     *
     * GET /api/v1/admin/audit/users/123/email-changes
     */
    @GetMapping("/users/{userId}/email-changes")
    @PreAuthorize("hasAnyRole('ADMIN', 'MASTER_ADMIN')")
    public ResponseEntity<List<UserAuditHistoryDTO>> getEmailChangeHistory(
            @PathVariable Long userId) {

        List<UserAuditHistoryDTO> history = userAuditService.getEmailChangeHistory(userId);
        return ResponseEntity.ok(history);
    }

    /**
     * Get password change history (for compliance)
     *
     * GET /api/v1/admin/audit/users/123/password-changes
     */
    @GetMapping("/users/{userId}/password-changes")
    @PreAuthorize("hasAnyRole('ADMIN', 'MASTER_ADMIN')")
    public ResponseEntity<List<UserAuditHistoryDTO>> getPasswordChangeHistory(
            @PathVariable Long userId) {

        List<UserAuditHistoryDTO> history = userAuditService.getPasswordChangeHistory(userId);
        return ResponseEntity.ok(history);
    }

    /**
     * ✅ NEW: Get role assignment/removal history for a user
     *
     * GET /api/v1/admin/audit/users/123/role-changes
     */
    @GetMapping("/users/{userId}/role-changes")
    @PreAuthorize("hasAnyRole('ADMIN', 'MASTER_ADMIN')")
    public ResponseEntity<List<RoleChangeHistoryDTO>> getRoleChangeHistory(
            @PathVariable Long userId) {

        List<RoleChangeHistoryDTO> history = userAuditService.getRoleChangeHistory(userId);
        return ResponseEntity.ok(history);
    }

    /**
     * ✅ NEW: Get all users who ever had a specific role
     *
     * GET /api/v1/admin/audit/roles/ROLE_ADMIN/users
     */
    @GetMapping("/roles/{roleName}/users")
    @PreAuthorize("hasRole('MASTER_ADMIN')")
    public ResponseEntity<List<RoleChangeHistoryDTO>> getUsersWithRole(
            @PathVariable String roleName) {

        List<RoleChangeHistoryDTO> history = userAuditService.getUsersWithRole(roleName);
        return ResponseEntity.ok(history);
    }

    /**
     * ✅ NEW: Track privilege escalation (security audit)
     *
     * GET /api/v1/admin/audit/privilege-escalations
     */
    @GetMapping("/privilege-escalations")
    @PreAuthorize("hasRole('MASTER_ADMIN')")
    public ResponseEntity<List<RoleChangeHistoryDTO>> getPrivilegeEscalations() {

        List<RoleChangeHistoryDTO> history = userAuditService.getPrivilegeEscalations();
        return ResponseEntity.ok(history);
    }

    /**
     * Get account enable/disable history
     *
     * GET /api/v1/admin/audit/users/123/status-changes
     */
    @GetMapping("/users/{userId}/status-changes")
    @PreAuthorize("hasAnyRole('ADMIN', 'MASTER_ADMIN')")
    public ResponseEntity<List<UserAuditHistoryDTO>> getAccountStatusChangeHistory(
            @PathVariable Long userId) {

        List<UserAuditHistoryDTO> history = userAuditService.getAccountStatusChangeHistory(userId);
        return ResponseEntity.ok(history);
    }

    /**
     * Get all changes made by a specific admin
     *
     * GET /api/v1/admin/audit/by-admin/john.doe@example.com
     */
    @GetMapping("/by-admin/{username}")
    @PreAuthorize("hasRole('MASTER_ADMIN')")
    public ResponseEntity<List<UserAuditHistoryDTO>> getChangesByAdmin(
            @PathVariable String username) {

        List<UserAuditHistoryDTO> history = userAuditService.getChangesByAdmin(username);
        return ResponseEntity.ok(history);
    }
}