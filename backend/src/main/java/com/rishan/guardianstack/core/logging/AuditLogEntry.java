package com.rishan.guardianstack.core.logging;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.rishan.guardianstack.auth.model.User;
import lombok.Builder;
import lombok.Getter;
import tools.jackson.databind.ObjectMapper;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * Structured log entry optimized for Elasticsearch indexing
 * Uses JSON format for easy parsing by Logstash
 */
@Getter
@Builder
public class AuditLogEntry {

    // ELK Standard Fields (ECS - Elastic Common Schema)
    @JsonProperty("@timestamp")
    private final Instant timestamp;

    @JsonProperty("event.type")
    private final String eventType;

    @JsonProperty("event.category")
    private final String eventCategory;

    @JsonProperty("event.outcome")
    private final String outcome; // "success" or "failure"

    // User Fields
    @JsonProperty("user.email")
    private final String userEmail;

    @JsonProperty("user.id")
    private final Long userId;

    @JsonProperty("user.name")
    private final String userName;

    // Network Fields
    @JsonProperty("source.ip")
    private final String sourceIp;

    @JsonProperty("user_agent.original")
    private final String userAgent;

    // Request Fields
    @JsonProperty("trace.id")
    private final String requestId;

    @JsonProperty("session.id")
    private final String sessionId;

    // Application Fields
    @JsonProperty("log.level")
    private final String logLevel;

    @JsonProperty("message")
    private final String message;

    @JsonProperty("labels")
    private final Map<String, String> labels;

    // Custom fields for specific use cases
    @JsonProperty("security.threat_level")
    private final String threatLevel;

    @JsonProperty("custom")
    private final Map<String, Object> customFields;

    private static final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Factory method for successful events
     */
    public static AuditLogEntry success(AuditEventType eventType, User user, String additionalInfo) {
        AuditContext.AuditMetadata context = AuditContext.get();

        Map<String, String> labels = new HashMap<>();
        labels.put("environment", "production");
        labels.put("application", "guardianstack");
        labels.put("module", "auth");

        return AuditLogEntry.builder()
                .timestamp(Instant.now())
                .eventType(eventType.name())
                .eventCategory(getEventCategory(eventType))
                .outcome("success")
                .userEmail(user != null ? user.getEmail() : null)
                .userId(user != null ? user.getUserId() : null)
                .userName(user != null ? user.getUsername() : null)
                .sourceIp(context != null ? context.getIpAddress() : "unknown")
                .userAgent(context != null ? context.getUserAgent() : "unknown")
                .requestId(context != null ? context.getRequestId() : null)
                .sessionId(context != null ? context.getSessionId() : null)
                .logLevel(eventType.getLevel().name())
                .message(additionalInfo != null ? additionalInfo : eventType.getDescription())
                .labels(labels)
                .threatLevel(getThreatLevel(eventType))
                .customFields(context != null ? new HashMap<>(context.getCustomFields()) : new HashMap<>())
                .build();
    }

    /**
     * Factory method for failed events
     */
    public static AuditLogEntry failure(AuditEventType eventType, String email, String reason) {
        AuditContext.AuditMetadata context = AuditContext.get();

        Map<String, String> labels = new HashMap<>();
        labels.put("environment", "production");
        labels.put("application", "guardianstack");
        labels.put("module", "auth");

        return AuditLogEntry.builder()
                .timestamp(Instant.now())
                .eventType(eventType.name())
                .eventCategory(getEventCategory(eventType))
                .outcome("failure")
                .userEmail(email)
                .userId(null)
                .userName(null)
                .sourceIp(context != null ? context.getIpAddress() : "unknown")
                .userAgent(context != null ? context.getUserAgent() : "unknown")
                .requestId(context != null ? context.getRequestId() : null)
                .sessionId(context != null ? context.getSessionId() : null)
                .logLevel(eventType.getLevel().name())
                .message(reason)
                .labels(labels)
                .threatLevel(getThreatLevel(eventType))
                .customFields(context != null ? new HashMap<>(context.getCustomFields()) : new HashMap<>())
                .build();
    }

    /**
     * Convert to JSON string for Logstash parsing
     */
    public String toJsonString() {
        return objectMapper.writeValueAsString(this);
    }

    /**
     * Formatted string for console (human-readable)
     */
    public String toFormattedString() {
        return String.format(
                "[%s] %s | User: %s | IP: %s | Success: %s | %s | RequestId: %s",
                timestamp,
                eventType,
                userEmail != null ? userEmail : "N/A",
                sourceIp,
                outcome,
                message,
                requestId != null ? requestId : "N/A"
        );
    }

    /**
     * Get event category for ECS compliance
     */
    private static String getEventCategory(AuditEventType eventType) {
        String name = eventType.name();
        if (name.contains("LOGIN") || name.contains("LOGOUT")) return "authentication";
        if (name.contains("TOKEN")) return "session";
        if (name.contains("PASSWORD")) return "iam";
        if (name.contains("ACCOUNT")) return "iam";
        if (name.contains("ADMIN")) return "configuration";
        return "authentication";
    }

    /**
     * Assess threat level for security analytics
     */
    private static String getThreatLevel(AuditEventType eventType) {
        return switch (eventType.getLevel()) {
            case CRITICAL -> "high";
            case WARN -> "medium";
            case INFO -> "low";
            case DEBUG -> "none";
        };
    }
}