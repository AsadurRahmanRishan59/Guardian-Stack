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
 * IMPORTANT: Uses AsyncAuditProcessor (separate service) to avoid self-invocation issues
 * with @Async annotations.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ELKAuditService {

    private final AuthAuditLogRepository authAuditLogRepository;
    private final AsyncAuditProcessor asyncAuditProcessor;

    private static final ThreadLocal<List<AuditLogEntry>> pendingLogs =
            ThreadLocal.withInitial(ArrayList::new);

    // ==========================================
    // PUBLIC API - TRANSACTION AWARE
    // ==========================================

    /**
     * Log success - automatically handles transaction state
     */
    public void logSuccess(AuditEventType eventType, User user, String additionalInfo) {
        AuditLogEntry entry = AuditLogEntry.success(eventType, user, additionalInfo);
        scheduleOrExecute(entry);
    }

    /**
     * Log failure - automatically handles transaction state
     */
    public void logFailure(AuditEventType eventType, String email, String reason) {
        AuditLogEntry entry = AuditLogEntry.failure(eventType, email, reason);
        scheduleOrExecute(entry);
    }

    /**
     * Force immediate logging (bypasses transaction buffer)
     * Use for non-transactional contexts or when you need guaranteed logging
     */
    public void logSuccessImmediately(AuditEventType eventType, User user, String additionalInfo) {
        AuditLogEntry entry = AuditLogEntry.success(eventType, user, additionalInfo);
        executeLogAsync(entry);
    }

    public void logFailureImmediately(AuditEventType eventType, String email, String reason) {
        AuditLogEntry entry = AuditLogEntry.failure(eventType, email, reason);
        executeLogAsync(entry);
    }

    // ==========================================
    // TRANSACTION MANAGEMENT
    // ==========================================

    private void scheduleOrExecute(AuditLogEntry entry) {
        if (!TransactionSynchronizationManager.isSynchronizationActive()) {
            // No active transaction - execute immediately
            executeLogAsync(entry);
            return;
        }

        // Buffer for after-commit
        pendingLogs.get().add(entry);

        // Register synchronization only once
        if (pendingLogs.get().size() == 1) {
            TransactionSynchronizationManager.registerSynchronization(
                    new TransactionSynchronization() {
                        @Override
                        public void afterCommit() {
                            List<AuditLogEntry> logs = pendingLogs.get();
                            log.debug("Transaction committed, flushing {} audit logs", logs.size());

                            // Send each log to async processor (separate service!)
                            logs.forEach(asyncAuditProcessor::processAuditLog);

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

    /**
     * Execute log asynchronously via separate service
     * CRITICAL: This calls asyncAuditProcessor (separate @Service) to ensure
     * the @Async annotation is properly intercepted by Spring AOP proxy.
     */
    private void executeLogAsync(AuditLogEntry entry) {
        asyncAuditProcessor.processAuditLog(entry);
    }

    /**
     * Log the fact that a transaction rolled back (for troubleshooting)
     */
    private void logRollbackEvent(List<AuditLogEntry> discardedLogs) {
        try {
            StringBuilder msg = new StringBuilder("Transaction rollback prevented logging of: ");
            discardedLogs.forEach(p -> msg.append(p.getEventType()).append(", "));

            log.warn("🔄 ROLLBACK DETECTED: {}", msg);

            // Optionally send a single "rollback occurred" event to ELK for debugging
            // This is sent immediately and not buffered
            AuditLogEntry rollbackEntry = AuditLogEntry.builder()
                    .eventType("TRANSACTION_ROLLBACK")
                    .message(msg.toString())
                    .timestamp(Instant.now())
                    .build();

            // Send to async processor
            asyncAuditProcessor.processAuditLog(rollbackEntry);

        } catch (Exception e) {
            log.error("Failed to log rollback event", e);
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
}