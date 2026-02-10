package com.rishan.guardianstack.auth.service;

import com.rishan.guardianstack.auth.dto.response.RoleChangeHistoryDTO;
import com.rishan.guardianstack.masteradmin.audit.user.UserAuditHistoryDTO;
import com.rishan.guardianstack.core.domain.CustomRevisionEntity;
import com.rishan.guardianstack.auth.model.User;
import jakarta.persistence.EntityManager;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.hibernate.envers.AuditReader;
import org.hibernate.envers.AuditReaderFactory;
import org.hibernate.envers.RevisionType;
import org.hibernate.envers.query.AuditEntity;
import org.hibernate.envers.query.AuditQuery;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.List;

/**
 * Service for querying Hibernate Envers audit history
 *
 * FIXED: Proper revision type handling using query results
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class UserAuditService {

    private final EntityManager entityManager;

    /**
     * Get complete audit history for a user
     */
    @Transactional(readOnly = true)
    public List<UserAuditHistoryDTO> getUserAuditHistory(Long userId) {
        AuditReader auditReader = AuditReaderFactory.get(entityManager);

        // Use forRevisionsOfEntity with selectEntitiesOnly=false and selectDeletedEntities=true
        // This returns Object[] with [entity, revisionEntity, revisionType]
        AuditQuery query = auditReader.createQuery()
                .forRevisionsOfEntity(User.class, false, true)
                .add(AuditEntity.id().eq(userId))
                .addOrder(AuditEntity.revisionNumber().desc());

        @SuppressWarnings("unchecked")
        List<Object[]> results = query.getResultList();

        return results.stream()
                .map(this::mapToAuditHistoryDTO)
                .toList();
    }

    /**
     * Get audit history within a date range
     */
    @Transactional(readOnly = true)
    public List<UserAuditHistoryDTO> getUserAuditHistoryBetween(
            Long userId,
            LocalDateTime from,
            LocalDateTime to) {

        AuditReader auditReader = AuditReaderFactory.get(entityManager);

        long fromTimestamp = toMillis(from);
        long toTimestamp = toMillis(to);

        AuditQuery query = auditReader.createQuery()
                .forRevisionsOfEntity(User.class, false, true)
                .add(AuditEntity.id().eq(userId))
                .add(AuditEntity.revisionProperty("timestamp").ge(fromTimestamp))
                .add(AuditEntity.revisionProperty("timestamp").le(toTimestamp))
                .addOrder(AuditEntity.revisionProperty("timestamp").desc());

        @SuppressWarnings("unchecked")
        List<Object[]> results = query.getResultList();

        return results.stream()
                .map(this::mapToAuditHistoryDTO)
                .toList();
    }

    /**
     * Get email change history for a user
     */
    @Transactional(readOnly = true)
    public List<UserAuditHistoryDTO> getEmailChangeHistory(Long userId) {
        AuditReader auditReader = AuditReaderFactory.get(entityManager);

        AuditQuery query = auditReader.createQuery()
                .forRevisionsOfEntity(User.class, false, true)
                .add(AuditEntity.id().eq(userId))
                .add(AuditEntity.property("email").hasChanged())
                .addOrder(AuditEntity.revisionProperty("timestamp").desc());

        @SuppressWarnings("unchecked")
        List<Object[]> results = query.getResultList();

        return results.stream()
                .map(this::mapToAuditHistoryDTO)
                .toList();
    }

    /**
     * Get password change history (for compliance)
     */
    @Transactional(readOnly = true)
    public List<UserAuditHistoryDTO> getPasswordChangeHistory(Long userId) {
        AuditReader auditReader = AuditReaderFactory.get(entityManager);

        AuditQuery query = auditReader.createQuery()
                .forRevisionsOfEntity(User.class, false, true)
                .add(AuditEntity.id().eq(userId))
                .add(AuditEntity.property("password").hasChanged())
                .addOrder(AuditEntity.revisionProperty("timestamp").desc());

        @SuppressWarnings("unchecked")
        List<Object[]> results = query.getResultList();

        return results.stream()
                .map(this::mapToAuditHistoryDTO)
                .toList();
    }

    /**
     * Get role assignment/removal history for a user
     * This queries the gs_user_roles_aud table
     */
    @Transactional(readOnly = true)
    public List<RoleChangeHistoryDTO> getRoleChangeHistory(Long userId) {
        // Use native SQL to query the join table audit
        String sql = """
                    SELECT 
                        ur.rev,
                        ur.revtype,
                        ur.user_id,
                        ur.role_id,
                        gr.role_name,
                        r.revtstmp,
                        r.username,
                        r.ip_address
                    FROM gs_user_roles_aud ur
                    JOIN revinfo r ON ur.rev = r.rev
                    JOIN gs_roles gr ON ur.role_id = gr.role_id
                    WHERE ur.user_id = :userId
                    ORDER BY r.revtstmp DESC
                """;

        @SuppressWarnings("unchecked")
        List<Object[]> results = entityManager.createNativeQuery(sql)
                .setParameter("userId", userId)
                .getResultList();

        return results.stream()
                .map(row -> RoleChangeHistoryDTO.builder()
                        .revisionNumber(((Number) row[0]).longValue())
                        .revisionType(mapRevisionType((Number) row[1]))
                        .userId(((Number) row[2]).longValue())
                        .roleId(((Number) row[3]).intValue())
                        .roleName((String) row[4])
                        .timestamp(toLocalDateTime(((Number) row[5]).longValue()))
                        .changedBy((String) row[6])
                        .ipAddress((String) row[7])
                        .userEmail(null) // Not in this query
                        .username(null)  // Not in this query
                        .build())
                .toList();
    }

    /**
     * Get all users who ever had a specific role
     */
    @Transactional(readOnly = true)
    public List<RoleChangeHistoryDTO> getUsersWithRole(String roleName) {
        String sql = """
                    SELECT DISTINCT
                        ur.rev,
                        ur.revtype,
                        ur.user_id,
                        ur.role_id,
                        gr.role_name,
                        r.revtstmp,
                        r.username,
                        r.ip_address,
                        u.email,
                        u.username as user_username
                    FROM gs_user_roles_aud ur
                    JOIN revinfo r ON ur.rev = r.rev
                    JOIN gs_roles gr ON ur.role_id = gr.role_id
                    JOIN gs_users u ON ur.user_id = u.user_id
                    WHERE gr.role_name = :roleName
                      AND ur.revtype = 0
                    ORDER BY r.revtstmp DESC
                """;

        @SuppressWarnings("unchecked")
        List<Object[]> results = entityManager.createNativeQuery(sql)
                .setParameter("roleName", roleName)
                .getResultList();

        return results.stream()
                .map(row -> RoleChangeHistoryDTO.builder()
                        .revisionNumber(((Number) row[0]).longValue())
                        .revisionType(mapRevisionType((Number) row[1]))
                        .userId(((Number) row[2]).longValue())
                        .roleId(((Number) row[3]).intValue())
                        .roleName((String) row[4])
                        .timestamp(toLocalDateTime(((Number) row[5]).longValue()))
                        .changedBy((String) row[6])
                        .ipAddress((String) row[7])
                        .userEmail((String) row[8])
                        .username((String) row[9])
                        .build())
                .toList();
    }

    /**
     * Track privilege escalation (non-admins becoming admins)
     */
    @Transactional(readOnly = true)
    public List<RoleChangeHistoryDTO> getPrivilegeEscalations() {
        String sql = """
                    SELECT 
                        ur.rev,
                        ur.revtype,
                        ur.user_id,
                        ur.role_id,
                        gr.role_name,
                        r.revtstmp,
                        r.username,
                        r.ip_address,
                        u.email,
                        u.username as user_username
                    FROM gs_user_roles_aud ur
                    JOIN revinfo r ON ur.rev = r.rev
                    JOIN gs_roles gr ON ur.role_id = gr.role_id
                    JOIN gs_users u ON ur.user_id = u.user_id
                    WHERE gr.role_name IN ('ROLE_ADMIN', 'ROLE_MASTER_ADMIN')
                      AND ur.revtype = 0
                    ORDER BY r.revtstmp DESC
                """;

        @SuppressWarnings("unchecked")
        List<Object[]> results = entityManager.createNativeQuery(sql)
                .getResultList();

        return results.stream()
                .map(row -> RoleChangeHistoryDTO.builder()
                        .revisionNumber(((Number) row[0]).longValue())
                        .revisionType(mapRevisionType((Number) row[1]))
                        .userId(((Number) row[2]).longValue())
                        .roleId(((Number) row[3]).intValue())
                        .roleName((String) row[4])
                        .timestamp(toLocalDateTime(((Number) row[5]).longValue()))
                        .changedBy((String) row[6])
                        .ipAddress((String) row[7])
                        .userEmail((String) row[8])
                        .username((String) row[9])
                        .build())
                .toList();
    }

    /**
     * Get account enable/disable history
     */
    @Transactional(readOnly = true)
    public List<UserAuditHistoryDTO> getAccountStatusChangeHistory(Long userId) {
        AuditReader auditReader = AuditReaderFactory.get(entityManager);

        AuditQuery query = auditReader.createQuery()
                .forRevisionsOfEntity(User.class, false, true)
                .add(AuditEntity.id().eq(userId))
                .add(AuditEntity.property("enabled").hasChanged())
                .addOrder(AuditEntity.revisionProperty("timestamp").desc());

        @SuppressWarnings("unchecked")
        List<Object[]> results = query.getResultList();

        return results.stream()
                .map(this::mapToAuditHistoryDTO)
                .toList();
    }

    /**
     * Get all changes made by a specific admin/user
     */
    @Transactional(readOnly = true)
    public List<UserAuditHistoryDTO> getChangesByAdmin(String username) {
        AuditReader auditReader = AuditReaderFactory.get(entityManager);

        AuditQuery query = auditReader.createQuery()
                .forRevisionsOfEntity(User.class, false, true)
                .add(AuditEntity.revisionProperty("username").eq(username))
                .addOrder(AuditEntity.revisionProperty("timestamp").desc());

        @SuppressWarnings("unchecked")
        List<Object[]> results = query.getResultList();

        return results.stream()
                .map(this::mapToAuditHistoryDTO)
                .toList();
    }

    /**
     * Get user state at a specific point in time
     */
    @Transactional(readOnly = true)
    public User getUserAtDate(Long userId, LocalDateTime date) {
        AuditReader auditReader = AuditReaderFactory.get(entityManager);

        // Envers requires java.util.Date for this specific method
        java.util.Date dateParam = java.util.Date.from(date.atZone(ZoneId.systemDefault()).toInstant());

        try {
            Number revision = auditReader.getRevisionNumberForDate(dateParam);
            return auditReader.find(User.class, userId, revision);
        } catch (org.hibernate.envers.exception.RevisionDoesNotExistException e) {
            log.warn("No revision found for user {} at date {}", userId, date);
            return null;
        }
    }

    // =========================================================================
    // HELPER METHODS
    // =========================================================================

    /**
     * ✅ FIXED: Map Object[] from query result to DTO
     *
     * Query with selectEntitiesOnly=false returns Object[] with:
     * [0] = Entity (User)
     * [1] = RevisionEntity (CustomRevisionEntity)
     * [2] = RevisionType (ADD, MOD, DEL)
     */
    private UserAuditHistoryDTO mapToAuditHistoryDTO(Object[] result) {
        User user = (User) result[0];
        CustomRevisionEntity revision = (CustomRevisionEntity) result[1];
        RevisionType revisionType = (RevisionType) result[2];

        return UserAuditHistoryDTO.builder()
                .revisionNumber(revision.getRev())
                .revisionType(revisionType.name())
                .timestamp(toLocalDateTime(revision.getTimestamp()))
                .changedBy(revision.getUsername())
                .ipAddress(revision.getIpAddress())
                .username(user.getUsername())
                .email(user.getEmail())
                .enabled(user.isEnabled())
                .accountLocked(user.isAccountLocked())
                .accountExpiryDate(user.getAccountExpiryDate())
                .credentialsExpiryDate(user.getCredentialsExpiryDate())
                .build();
    }

    private String mapRevisionType(Number revtype) {
        int type = revtype.intValue();
        return switch (type) {
            case 0 -> "ADD";
            case 1 -> "MOD";
            case 2 -> "DEL";
            default -> "UNKNOWN";
        };
    }

    private LocalDateTime toLocalDateTime(Long milliseconds) {
        return LocalDateTime.ofInstant(
                Instant.ofEpochMilli(milliseconds),
                ZoneId.systemDefault()
        );
    }

    private long toMillis(LocalDateTime dateTime) {
        return dateTime.atZone(ZoneId.systemDefault()).toInstant().toEpochMilli();
    }
}