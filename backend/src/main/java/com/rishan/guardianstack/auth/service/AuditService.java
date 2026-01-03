package com.rishan.guardianstack.auth.service;

import com.rishan.guardianstack.auth.model.AuditLog;
import com.rishan.guardianstack.auth.model.User;
import com.rishan.guardianstack.auth.repository.AuditLogRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuditService {

    private final AuditLogRepository auditLogRepository;

    /**
     * Logs a security event asynchronously
     */
    @Async
    @Transactional
    public void logEvent(String eventType, User user, boolean success,
                         String ipAddress, String userAgent, String additionalInfo) {
        try {
            AuditLog auditLog = AuditLog.builder()
                    .eventType(eventType)
                    .userEmail(user != null ? user.getEmail() : null)
                    .userId(user != null ? user.getUserId() : null)
                    .ipAddress(ipAddress)
                    .userAgent(userAgent)
                    .success(success)
                    .additionalInfo(additionalInfo)
                    .build();

            auditLogRepository.save(auditLog);
            log.info("Audit log created: {} for user: {}", eventType,
                    user != null ? user.getEmail() : "N/A");
        } catch (Exception e) {
            log.error("Failed to create audit log", e);
        }
    }

    /**
     * Logs a failed event with reason
     */
    @Async
    @Transactional
    public void logFailedEvent(String eventType, String email, String failureReason,
                               String ipAddress, String userAgent) {
        try {
            AuditLog auditLog = AuditLog.builder()
                    .eventType(eventType)
                    .userEmail(email)
                    .ipAddress(ipAddress)
                    .userAgent(userAgent)
                    .success(false)
                    .failureReason(failureReason)
                    .build();

            auditLogRepository.save(auditLog);
            log.warn("Failed event logged: {} for email: {}", eventType, email);
        } catch (Exception e) {
            log.error("Failed to create audit log", e);
        }
    }

    /**
     * Helper method to extract IP from request
     */
    public String getClientIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("X-Real-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }
        // Handle multiple IPs (take the first one)
        if (ip != null && ip.contains(",")) {
            ip = ip.split(",")[0].trim();
        }
        return ip;
    }

    /**
     * Helper method to get user agent
     */
    public String getUserAgent(HttpServletRequest request) {
        return request.getHeader("User-Agent");
    }

    /**
     * Get audit logs for a user
     */
    public List<AuditLog> getUserAuditLogs(Long userId) {
        return auditLogRepository.findByUserIdOrderByTimestampDesc(userId);
    }

    /**
     * Clean up old audit logs (older than 90 days)
     */
    @Transactional
    public int cleanupOldLogs(int daysToKeep) {
        LocalDateTime cutoffDate = LocalDateTime.now().minusDays(daysToKeep);
        return auditLogRepository.deleteOldLogs(cutoffDate);
    }
}