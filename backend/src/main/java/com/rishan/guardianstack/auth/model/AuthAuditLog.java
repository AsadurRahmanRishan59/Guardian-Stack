package com.rishan.guardianstack.auth.model;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Entity
@Table(name = "gs_auth_audit_logs")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthAuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "event_type", nullable = false, length = 50)
    private String eventType; // LOGIN, LOGOUT, PASSWORD_RESET, etc.

    @Column(name = "user_email", length = 255)
    private String userEmail;

    @Column(name = "user_id")
    private Long userId;

    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    @Column(name = "user_agent", length = 500)
    private String userAgent;

    @Column(name = "success", nullable = false)
    private boolean success;

    @Column(name = "failure_reason", length = 500)
    private String failureReason;

    @Column(name = "additional_info", length = 1000)
    private String additionalInfo;

    @CreationTimestamp
    @Column(name = "timestamp", nullable = false, updatable = false)
    private LocalDateTime timestamp;
}