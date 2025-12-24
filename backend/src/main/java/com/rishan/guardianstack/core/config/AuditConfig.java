package com.rishan.guardianstack.core.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.AuditorAware;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Objects;
import java.util.Optional;

@Configuration
@EnableJpaAuditing // This is the "on switch" for @CreatedBy and @CreatedDate
public class AuditConfig {

    @Bean
    public AuditorAware<String> auditorProvider() {
        return () -> {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            // If no one is logged in (like during Public Signup), we return "SYSTEM"
            if (authentication == null || !authentication.isAuthenticated() ||
                    Objects.equals(authentication.getPrincipal(), "anonymousUser")) {
                return Optional.of("SYSTEM");
            }

            // If an Admin or Employee is logged in, we return their username
            return Optional.of(authentication.getName());
        };
    }
}