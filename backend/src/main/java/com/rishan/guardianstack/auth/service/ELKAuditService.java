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
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * Dual-destination audit service with transaction-awareness
 * - ALL events -> Elasticsearch (via Logstash)
 * - CRITICAL events -> PostgresSQL (for compliance)
 * - Logs buffered during transactions and sent only after commit
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ELKAuditService {

    private final AuthAuditLogRepository authAuditLogRepository;
    private final AuditDbWriter auditDbWriter;

    private static final ThreadLocal<List<PendingAuditLog>> pendingLogs =
            ThreadLocal.withInitial(ArrayList::new);

    // ==========================================
    // PUBLIC API - TRANSACTION AWARE
    // ==========================================

    /**
     * Log success - automatically handles transaction state
     */
    public void logSuccess(AuditEventType eventType, User user, String additionalInfo) {
        PendingAuditLog pending = new PendingAuditLog(
                AuditLogEntry.success(eventType, user, additionalInfo),
                true,
                user,
                null,
                additionalInfo
        );
        scheduleOrExecute(pending);
    }

    /**
     * Log failure - automatically handles transaction state
     */
    public void logFailure(AuditEventType eventType, String email, String reason) {
        PendingAuditLog pending = new PendingAuditLog(
                AuditLogEntry.failure(eventType, email, reason),
                false,
                null,
                email,
                reason
        );
        scheduleOrExecute(pending);
    }

    /**
     * Force immediate logging (bypasses transaction buffer)
     * Use for non-transactional contexts or when you need guaranteed logging
     */
    public void logSuccessImmediately(AuditEventType eventType, User user, String additionalInfo) {
        AuditLogEntry entry = AuditLogEntry.success(eventType, user, additionalInfo);
        executeLog(entry, true, user, null, additionalInfo);
    }

    public void logFailureImmediately(AuditEventType eventType, String email, String reason) {
        AuditLogEntry entry = AuditLogEntry.failure(eventType, email, reason);
        executeLog(entry, false, null, email, reason);
    }

    // ==========================================
    // TRANSACTION MANAGEMENT
    // ==========================================

    private void scheduleOrExecute(PendingAuditLog pending) {
        if (!TransactionSynchronizationManager.isSynchronizationActive()) {
            // No active transaction - execute immediately
            executeLog(pending.entry, pending.isSuccess, pending.user, pending.email, pending.info);
            return;
        }

        // Buffer for after-commit
        pendingLogs.get().add(pending);

        // Register synchronization only once
        if (pendingLogs.get().size() == 1) {
            TransactionSynchronizationManager.registerSynchronization(
                    new TransactionSynchronization() {
                        @Override
                        public void afterCommit() {
                            List<PendingAuditLog> logs = pendingLogs.get();
                            log.debug("Transaction committed, flushing {} audit logs", logs.size());

                            logs.forEach(pending ->
                                    executeLog(pending.entry, pending.isSuccess,
                                            pending.user, pending.email, pending.info)
                            );

                            pendingLogs.remove();
                        }

                        @Override
                        public void afterCompletion(int status) {
                            if (status == STATUS_ROLLED_BACK) {
                                int discarded = pendingLogs.get().size();
                                log.warn("⚠️ Transaction ROLLED BACK - discarding {} audit logs to prevent inconsistency",
                                        discarded);

                                // Optional: Log the rollback itself (immediately, not buffered)
                                if (discarded > 0) {
                                    logRollbackEvent(pendingLogs.get());
                                }

                                pendingLogs.remove();
                            }
                        }
                    }
            );
        }
    }

    private void executeLog(AuditLogEntry entry, boolean isSuccess,
                            User user, String email, String info) {
        if (isSuccess) {
            processSuccessLog(entry, user, info);
        } else {
            processFailureLog(entry, email, info);
        }
    }

    /**
     * Execute log asynchronously - called AFTER transaction commit
     * or immediately for non-transactional contexts
     */
    @Async("auditLogExecutor")
    protected void processSuccessLog(AuditLogEntry entry, User user, String info) {
        processLog(entry);
    }

    @Async("auditLogExecutor")
    protected void processFailureLog(AuditLogEntry entry, String email, String info) {
        processLog(entry);
    }

    /**
     * Process the log entry synchronously within the async thread
     * This sends to both ELK and DB as needed
     */
    private void processLog(AuditLogEntry entry) {
        try {
            // Send to Elasticsearch
            if (entry.getEventType() != null &&
                    AuditEventType.valueOf(entry.getEventType()).shouldLogToElasticsearch()) {
                logToElasticsearch(entry);
            }

            // Send to PostgresSQL
            if (entry.getEventType() != null &&
                    AuditEventType.valueOf(entry.getEventType()).shouldPersistToDatabase()) {
                auditDbWriter.saveToDatabase(entry);
            }
        } catch (Exception e) {
            log.error("Failed to process audit log for event: {}", entry.getEventType(), e);
        }
    }

    /**
     * Log the fact that a transaction rolled back (for troubleshooting)
     */
    private void logRollbackEvent(List<PendingAuditLog> discardedLogs) {
        try {
            StringBuilder msg = new StringBuilder("Transaction rollback prevented logging of: ");
            discardedLogs.forEach(p -> msg.append(p.entry.getEventType()).append(", "));

            log.warn("🔄 ROLLBACK DETECTED: {}", msg);

            // Optionally send a single "rollback occurred" event to ELK for debugging
            // This is sent immediately and not buffered
            AuditLogEntry rollbackEntry = AuditLogEntry.builder()
                    .eventType("TRANSACTION_ROLLBACK")
                    .message(msg.toString())
                    .timestamp(Instant.now())
                    .build();

            logToElasticsearch(rollbackEntry);

        } catch (Exception e) {
            log.error("Failed to log rollback event", e);
        }
    }

    /**
     * Log to Elasticsearch via Logstash (using structured JSON)
     */
    private void logToElasticsearch(AuditLogEntry entry) {
        try {
            AuditEventType eventType = AuditEventType.valueOf(entry.getEventType());

            switch (eventType.getLevel()) {
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
    // QUERY METHODS
    // ==========================================

    public List<AuthAuditLog> getUserAuditLogs(Long userId) {
        return authAuditLogRepository.findByUserIdOrderByTimestampDesc(userId);
    }

    @Scheduled(cron = "${app.security.audit.cleanup.cron:0 0 3 * * ?}")
    @Transactional
    public void cleanupOldDatabaseLogs() {
        LocalDateTime cutoff = LocalDateTime.now().minusDays(90);
        int deleted = authAuditLogRepository.deleteOldLogs(cutoff);
        log.info("🧹 PostgresSQL audit cleanup: Removed {} logs older than {}", deleted, cutoff);
    }

    // ==========================================
    // HELPER CLASSES
    // ==========================================

    private record PendingAuditLog(
            AuditLogEntry entry,
            boolean isSuccess,
            User user,
            String email,
            String info
    ) {}
}