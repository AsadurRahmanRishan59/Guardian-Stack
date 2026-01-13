package com.rishan.guardianstack.auth.model;

import com.rishan.guardianstack.core.domain.BaseEntity;
import jakarta.persistence.*;
import lombok.*;

import java.time.Duration;
import java.time.LocalDateTime;

@Entity
@Table(name = "gs_verification_tokens")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class VerificationToken extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long tokenId;

    @Column(nullable = false, length = 10)
    private String token;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false)
    private LocalDateTime expiryDate;

    @Column(nullable = false, length = 20)
    private String tokenType;

    @Column(nullable = false)
    @Builder.Default
    private Boolean verified = false;

    private LocalDateTime verifiedAt;

    @Column(nullable = false)
    @Builder.Default
    private Integer verificationAttempts = 0;

    @Column(nullable = false)
    @Builder.Default
    private LocalDateTime createdAt = LocalDateTime.now();

    public void incrementAttempts() {
        this.verificationAttempts++;
    }

    public boolean isExpired() {
        return LocalDateTime.now().isAfter(this.expiryDate);
    }

    public long getRemainingMinutes() {
        if (isExpired()) {
            return 0;
        }
        return Duration.between(LocalDateTime.now(), this.expiryDate).toMinutes();
    }
}