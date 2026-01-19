package com.rishan.guardianstack.auth.service;

import com.rishan.guardianstack.core.logging.AuditEventType;
import com.rishan.guardianstack.core.logging.AuditLogEntry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.logstash.logback.marker.Markers;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

/**
 * Separate service for async audit log processing.
 * CRITICAL: This must be a separate @Service to avoid self-invocation issues.
 * When @Async methods are called from within the same class, Spring's AOP proxy
 * is bypassed and the method executes synchronously on the caller's thread.
 * By extracting to a separate service, Spring can properly intercept the call
 * and execute it asynchronously on the audit-log thread pool.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AsyncAuditProcessor {

    private final AuditDbWriter auditDbWriter;

    /**
     * Process audit log entry asynchronously.
     * This method is called AFTER transaction commit or immediately for non-transactional events.
     *
     * @param entry The audit log entry to process
     */
    @Async("auditLogExecutor")
    public void processAuditLog(AuditLogEntry entry) {
        try {
            // Send to Elasticsearch via Logstash
            if (entry.getEventType() != null &&
                    AuditEventType.valueOf(entry.getEventType()).shouldLogToElasticsearch()) {
                logToElasticsearch(entry);
            }

            // Send to PostgresSQL for critical events
            if (entry.getEventType() != null &&
                    AuditEventType.valueOf(entry.getEventType()).shouldPersistToDatabase()) {
                auditDbWriter.saveToDatabase(entry);
            }
        } catch (Exception e) {
            log.error("Failed to process audit log for event: {}", entry.getEventType(), e);
        }
    }

    /**
     * Log to Elasticsearch via Logstash (using structured JSON)
     * Logback + Logstash encoder will format this properly
     */
    private void logToElasticsearch(AuditLogEntry entry) {
        try {
            AuditEventType eventType = AuditEventType.valueOf(entry.getEventType());

            switch (eventType.getLevel()) {
                case DEBUG -> log.debug(
                        Markers.appendRaw("audit", entry.toJsonString()),
                        "AUDIT: {}", entry.getMessage()
                );
                case INFO -> log.info(
                        Markers.appendRaw("audit", entry.toJsonString()),
                        "AUDIT: {}", entry.getMessage()
                );
                case WARN -> log.warn(
                        Markers.appendRaw("audit", entry.toJsonString()),
                        "AUDIT: {}", entry.getMessage()
                );
                case CRITICAL -> log.error(
                        Markers.appendRaw("audit", entry.toJsonString()),
                        "🚨 SECURITY AUDIT: {}", entry.getMessage()
                );
            }
        } catch (Exception e) {
            log.error("Failed to log to Elasticsearch: {}", entry.getEventType(), e);
        }
    }
}