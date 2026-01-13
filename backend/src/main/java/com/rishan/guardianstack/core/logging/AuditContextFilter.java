package com.rishan.guardianstack.core.logging;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import com.rishan.guardianstack.auth.service.ELKAuditService;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class AuditContextFilter extends OncePerRequestFilter {

    private final ELKAuditService auditService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        try {
            // STEP 1: Capture the IP/Device info into AuditContext immediately
            auditService.setRequestContext(request, null);

            // STEP 2: Put the unique Request ID in the response header for debugging
            AuditContext.AuditMetadata metadata = AuditContext.get();
            if (metadata != null) {
                response.setHeader("X-Request-ID", metadata.getRequestId());
            }

            filterChain.doFilter(request, response);
        } finally {
            // STEP 3: Wipe the thread clean so User A's info doesn't leak to User B
            AuditContext.clear();
        }
    }
}