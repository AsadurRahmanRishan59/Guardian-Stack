package com.rishan.guardianstack.auth.service;

import com.rishan.guardianstack.auth.model.AuthAuditLog;
import com.rishan.guardianstack.auth.repository.AuthAuditLogRepository;
import com.rishan.guardianstack.core.logging.AuditLogEntry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
@RequiredArgsConstructor
@Slf4j
public class AuditDbWriter {

    private final AuthAuditLogRepository authAuditLogRepository;

    @Transactional
    public void saveToDatabase(AuditLogEntry entry) {
        try {
            AuthAuditLog auditLog = AuthAuditLog.builder()
                    .eventType(entry.getEventType())
                    .userEmail(entry.getUserEmail())
                    .userId(entry.getUserId())
                    .ipAddress(entry.getSourceIp())
                    .userAgent(entry.getUserAgent())
                    .success("success".equals(entry.getOutcome()))
                    .additionalInfo(entry.getMessage())
                    .failureReason("failure".equals(entry.getOutcome()) ? entry.getMessage() : null)
                    .build();

            authAuditLogRepository.save(auditLog);
        } catch (Exception e) {
            log.error("Failed to persist audit log to PostgreSQL for event: {}",
                    entry.getEventType(), e);
        }
    }
}