package com.rishan.guardianstack.core.domain;

import jakarta.servlet.http.HttpServletRequest;
import org.hibernate.envers.RevisionListener;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Custom Revision Listener for Envers
 *
 * This is called automatically by Hibernate Envers whenever a new revision is created.
 * We use it to populate the username and IP address fields in our custom revision entity.
 *
 * IMPORTANT: This runs BEFORE the transaction commits, so we can capture
 * the current user and request information.
 */
public class CustomRevisionListener implements RevisionListener {

    @Override
    public void newRevision(Object revisionEntity) {
        CustomRevisionEntity customRevision = (CustomRevisionEntity) revisionEntity;

        // Get the current authenticated user from Spring Security context
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated()) {
            customRevision.setUsername(authentication.getName());
        } else {
            customRevision.setUsername("SYSTEM");  // For system-initiated changes
        }

        // Get the IP address from the current HTTP request
        try {
            ServletRequestAttributes attributes =
                    (ServletRequestAttributes) RequestContextHolder.currentRequestAttributes();

            if (attributes != null) {
                HttpServletRequest request = attributes.getRequest();
                customRevision.setIpAddress(extractIpAddress(request));
            }
        } catch (IllegalStateException e) {
            // No request context available (e.g., background job, scheduled task)
            customRevision.setIpAddress("INTERNAL");
        }
    }

    /**
     * Extract IP address from request, handling proxies and load balancers
     */
    private String extractIpAddress(HttpServletRequest request) {
        // Check common proxy headers
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("X-Real-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("Proxy-Client-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("WL-Proxy-Client-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }

        // Handle multiple IPs in X-Forwarded-For (take the first one)
        if (ip != null && ip.contains(",")) {
            ip = ip.split(",")[0].trim();
        }

        return ip != null ? ip : "UNKNOWN";
    }
}