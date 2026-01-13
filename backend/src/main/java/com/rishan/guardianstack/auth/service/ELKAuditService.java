package com.rishan.guardianstack.auth.service;

import com.rishan.guardianstack.auth.model.AuthAuditLog;
import com.rishan.guardianstack.auth.model.User;
import com.rishan.guardianstack.auth.repository.AuthAuditLogRepository;
import com.rishan.guardianstack.core.logging.AuditContext;
import com.rishan.guardianstack.core.logging.AuditEventType;
import com.rishan.guardianstack.core.logging.AuditLogEntry;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.logstash.logback.marker.Markers;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Dual-destination audit service
 * - ALL events -> Elasticsearch (via Logstash)
 * - CRITICAL events -> PostgreSQL (for compliance)
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ELKAuditService {

    private final AuthAuditLogRepository authAuditLogRepository;

    /**
     * Main logging method - routes to appropriate destinations
     */
    @Async
    public void log(AuditLogEntry entry) {
        // ALWAYS log to Elasticsearch (via structured JSON logging)
        if (entry.getEventType() != null &&
                AuditEventType.valueOf(entry.getEventType()).shouldLogToElasticsearch()) {
            logToElasticsearch(entry);
        }

        // SELECTIVELY persist to PostgreSQL (only critical events)
        if (entry.getEventType() != null &&
                AuditEventType.valueOf(entry.getEventType()).shouldPersistToDatabase()) {
            persistToDatabase(entry);
        }
    }

    /**
     * Convenience method for successful events
     */
    public void logSuccess(AuditEventType eventType, User user, String additionalInfo) {
        AuditLogEntry entry = AuditLogEntry.success(eventType, user, additionalInfo);
        log(entry);
    }

    /**
     * Convenience method for failed events
     */
    public void logFailure(AuditEventType eventType, String email, String reason) {
        AuditLogEntry entry = AuditLogEntry.failure(eventType, email, reason);
        log(entry);
    }

    /**
     * Log to Elasticsearch via Logstash (using structured JSON)
     * Logback + Logstash encoder will format this properly
     */
    private void logToElasticsearch(AuditLogEntry entry) {
        try {
            // Use Logstash markers for structured logging
            switch (AuditEventType.valueOf(entry.getEventType()).getLevel()) {
                case DEBUG -> log.debug(Markers.appendRaw("audit", entry.toJsonString()),
                        "AUDIT: {}", entry.getMessage());
                case INFO -> log.info(Markers.appendRaw("audit", entry.toJsonString()),
                        "AUDIT: {}", entry.getMessage());
                case WARN -> log.warn(Markers.appendRaw("audit", entry.toJsonString()),
                        "AUDIT: {}", entry.getMessage());
                case CRITICAL -> log.error(Markers.appendRaw("audit", entry.toJsonString()),
                        "🚨 SECURITY AUDIT: {}", entry.getMessage());
            }
        } catch (Exception e) {
            log.error("Failed to log to Elasticsearch: {}", entry.getEventType(), e);
        }
    }

    /**
     * Persist critical events to PostgreSQL for compliance
     */
    @Transactional
    protected void persistToDatabase(AuditLogEntry entry) {
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
            log.error("Failed to persist audit log to database: {}",
                    entry.getEventType(), e);
        }
    }

    // ==========================================
    // REQUEST CONTEXT HELPERS
    // ==========================================

    public void setRequestContext(HttpServletRequest request, String userId) {
        String requestId = request.getHeader("X-Request-ID");
        if (requestId == null) {
            requestId = java.util.UUID.randomUUID().toString();
        }

        String sessionId = request.getSession(false) != null
                ? request.getSession().getId()
                : null;

        AuditContext.set(new AuditContext.AuditMetadata(
                getClientIp(request),
                request.getHeader("User-Agent"),
                requestId,
                userId,
                sessionId
        ));
    }

    public String getClientIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("X-Real-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }
        if (ip != null && ip.contains(",")) {
            ip = ip.split(",")[0].trim();
        }
        return ip;
    }

    // ==========================================
    // QUERY METHODS (PostgreSQL only for compliance)
    // ==========================================

    public List<AuthAuditLog> getUserAuditLogs(Long userId) {
        return authAuditLogRepository.findByUserIdOrderByTimestampDesc(userId);
    }

//    public List<AuthAuditLog> getCriticalSecurityEvents(LocalDateTime since) {
//        // Query PostgreSQL for critical events (for compliance reports)
//        return authAuditLogRepository.findCriticalEventsSince(since);
//    }

    /**
     * Cleanup OLD PostgreSQL logs (keep only 90 days for compliance)
     * Elasticsearch has its own retention policy (ILM)
     */
    @Scheduled(cron = "${app.security.audit.cleanup.cron:0 0 3 * * ?}")
    @Transactional
    public void cleanupOldDatabaseLogs() {
        LocalDateTime cutoff = LocalDateTime.now().minusDays(90);
        int deleted = authAuditLogRepository.deleteOldLogs(cutoff);
        log.info("🧹 PostgreSQL audit cleanup: Removed {} logs older than {}", deleted, cutoff);
    }
}