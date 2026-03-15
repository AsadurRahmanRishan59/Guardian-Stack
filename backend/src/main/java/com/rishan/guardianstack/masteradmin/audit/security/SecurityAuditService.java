package com.rishan.guardianstack.masteradmin.audit.security;

import com.rishan.guardianstack.auth.model.AuthAuditLog;
import com.rishan.guardianstack.auth.repository.AuthAuditLogRepository;
import com.rishan.guardianstack.core.logging.AuditEventType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import jakarta.persistence.criteria.Predicate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional(readOnly = true)
public class SecurityAuditService {

    private final AuthAuditLogRepository authAuditLogRepository;

    private static final Set<String> PERSISTENT_EVENT_TYPES =
            Arrays.stream(AuditEventType.values())
                    .filter(AuditEventType::shouldPersistToDatabase)
                    .map(Enum::name)
                    .collect(Collectors.toUnmodifiableSet());

    public Page<SecurityAuditTimelineItemDTO> getTimelineItems(SecurityAuditFilterRequest filter) {
        Pageable pageable = PageRequest.of(
                filter.page(),
                filter.size(),
                Sort.by(Sort.Direction.DESC, "timestamp"));

        return authAuditLogRepository
                .findAll(buildSpec(filter), pageable)
                .map(this::toTimelineItem);
    }

    private Specification<AuthAuditLog> buildSpec(SecurityAuditFilterRequest f) {
        return (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();

            // Always scope to DB-persistent event types
            predicates.add(root.get("eventType").in(PERSISTENT_EVENT_TYPES));

            if (f.eventType() != null && !f.eventType().isBlank()) {
                predicates.add(cb.equal(root.get("eventType"), f.eventType().trim()));
            }

            if (f.userEmail() != null && !f.userEmail().isBlank()) {
                predicates.add(cb.like(
                        cb.lower(root.get("userEmail")),
                        "%" + f.userEmail().trim().toLowerCase() + "%"));
            }

            if (f.ipAddress() != null && !f.ipAddress().isBlank()) {
                predicates.add(cb.like(
                        root.get("ipAddress"),
                        "%" + f.ipAddress().trim() + "%"));
            }

            // requestId: exact match — the index on this column makes it instant.
            // Partial/like search is intentionally avoided: UUIDs are opaque identifiers,
            // not human-readable strings, so a partial match would produce confusing results.
            if (f.requestId() != null && !f.requestId().isBlank()) {
                predicates.add(cb.equal(root.get("requestId"), f.requestId().trim()));
            }

            if (f.success() != null) {
                predicates.add(cb.equal(root.get("success"), f.success()));
            }

            if (f.from() != null) {
                predicates.add(cb.greaterThanOrEqualTo(root.get("timestamp"), f.from()));
            }

            if (f.to() != null) {
                predicates.add(cb.lessThanOrEqualTo(root.get("timestamp"), f.to()));
            }

            return cb.and(predicates.toArray(new Predicate[0]));
        };
    }

    private SecurityAuditTimelineItemDTO toTimelineItem(AuthAuditLog auditLog) {
        String description = "Unknown event";
        String level       = "INFO";
        try {
            AuditEventType type = AuditEventType.valueOf(auditLog.getEventType());
            description = type.getDescription();
            level       = type.getLevel().name();
        } catch (IllegalArgumentException e) {
            log.warn("Unknown AuditEventType '{}' found in DB row id={}",
                    auditLog.getEventType(), auditLog.getId());
        }

        return new SecurityAuditTimelineItemDTO(
                auditLog.getId(),
                auditLog.getEventType(),
                description,
                level,
                auditLog.getUserEmail(),
                auditLog.getUserId(),
                auditLog.getIpAddress(),
                auditLog.getUserAgent(),
                auditLog.getRequestId(),
                auditLog.isSuccess(),
                auditLog.getFailureReason(),
                auditLog.getAdditionalInfo(),
                auditLog.getTimestamp()
        );
    }
}