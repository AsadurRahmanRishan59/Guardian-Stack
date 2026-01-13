package com.rishan.guardianstack.core.logging;

import org.slf4j.MDC;

import java.util.Map;
import java.util.HashMap;

/**
 * Thread-safe context holder with MDC integration for ELK
 */
public class AuditContext {

    private static final ThreadLocal<AuditMetadata> context = new ThreadLocal<>();

    public static void set(AuditMetadata metadata) {
        context.set(metadata);

        // Set MDC for Logback (used by Logstash)
        MDC.put("requestId", metadata.getRequestId());
        MDC.put("userId", metadata.getUserId() != null ? metadata.getUserId() : "anonymous");
        MDC.put("ipAddress", metadata.getIpAddress());
        MDC.put("sessionId", metadata.getSessionId());
    }

    public static AuditMetadata get() {
        return context.get();
    }

    public static void clear() {
        context.remove();

        // Clear MDC
        MDC.remove("requestId");
        MDC.remove("userId");
        MDC.remove("ipAddress");
        MDC.remove("sessionId");
    }

    public static class AuditMetadata {
        private final String ipAddress;
        private final String userAgent;
        private final String requestId;
        private String userId;
        private final String sessionId;
        private final Map<String, String> customFields; // For ELK additional fields

        public AuditMetadata(String ipAddress, String userAgent, String requestId,
                             String userId, String sessionId) {
            this.ipAddress = ipAddress;
            this.userAgent = userAgent;
            this.requestId = requestId;
            this.userId = userId;
            this.sessionId = sessionId;
            this.customFields = new HashMap<>();
        }

        // Getters
        public String getIpAddress() {
            return ipAddress;
        }

        public String getUserAgent() {
            return userAgent;
        }

        public String getRequestId() {
            return requestId;
        }

        public String getUserId() {
            return userId;
        }

        public String getSessionId() {
            return sessionId;
        }

        public Map<String, String> getCustomFields() {
            return customFields;
        }

        // For adding custom ELK fields
        public void addCustomField(String key, String value) {
            this.customFields.put(key, value);
        }

        public void updateUserId(String userId) {
            this.userId = userId;
            MDC.put("userId", userId != null ? userId : "anonymous");
        }
    }
}