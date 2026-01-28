
package com.rishan.guardianstack.core.ratelimit;

import com.rishan.guardianstack.auth.dto.request.LoginRequestDTO;
import com.rishan.guardianstack.auth.service.ELKAuditService;
import com.rishan.guardianstack.core.exception.RateLimitExceededException;
import com.rishan.guardianstack.core.logging.AuditContext;
import com.rishan.guardianstack.core.logging.AuditEventType;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

@Aspect
@Component
@Slf4j
@RequiredArgsConstructor
public class RateLimitAspect {

    private final Map<String, RateLimitBucket> buckets = new ConcurrentHashMap<>();
    private final ELKAuditService auditService;

    @Around("@annotation(rateLimited)")
    public Object checkRateLimit(ProceedingJoinPoint joinPoint, RateLimited rateLimited) throws Throwable {
        String key = generateKey(joinPoint, rateLimited);

        RateLimitBucket bucket = buckets.computeIfAbsent(key, k ->
                new RateLimitBucket(
                        rateLimited.maxAttempts(),
                        rateLimited.timeWindow(),
                        rateLimited.unit()
                )
        );

        if (!bucket.tryConsume()) {
            int retryAfter = bucket.getSecondsUntilReset();

            // LOGIC TO IDENTIFY THE USER
            String identifier = "anonymous";
            var metadata = AuditContext.get();

            if (metadata != null && metadata.getUserId() != null && !metadata.getUserId().equals("anonymous")) {
                // User is logged in
                identifier = metadata.getUserId();
            } else {
                // Check if it's a login attempt and extract email from arguments
                identifier = attemptToExtractEmail(joinPoint);
            }

            auditService.logFailureImmediately(
                    AuditEventType.RATE_LIMIT_EXCEEDED,
                    identifier, // This tells us WHO reached the limit
                    String.format("Key: %s | Blocked for %d seconds", key, retryAfter)
            );
            throw new RateLimitExceededException(
                    String.format("Too many requests. Please try again in %d seconds.", retryAfter)

            );
        }

        return joinPoint.proceed();
    }

    private String generateKey(ProceedingJoinPoint joinPoint, RateLimited rateLimited) {
        ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attrs == null) {
            return "global-fallback-key";
        }

        HttpServletRequest request = attrs.getRequest();
        String ip = getClientIp(request);
        String method = joinPoint.getSignature().getName();

        // Combine IP + UserAgent for a more specific fingerprint if user is not logged in
        String userAgent = request.getHeader("User-Agent");
        String fingerprint = (userAgent != null) ? String.valueOf(userAgent.hashCode()) : "no-ua";

        return String.format("%s:%s:%s", method, ip, fingerprint);
    }

    private String attemptToExtractEmail(ProceedingJoinPoint joinPoint) {
        for (Object arg : joinPoint.getArgs()) {
            if (arg == null) continue;

            // Use Reflection or a shared interface to get email from any DTO
            try {
                // Check if the DTO has an email() method (for Records) or getEmail()
                var method = arg.getClass().getMethod("email");
                return (String) method.invoke(arg);
            } catch (Exception e) {
                try {
                    var method = arg.getClass().getMethod("getEmail");
                    return (String) method.invoke(arg);
                } catch (Exception e2) {
                    // Not a DTO with email, continue to next arg
                }
            }
        }
        return "anonymous";
    }

    private String getClientIp(HttpServletRequest request) {
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

    // Simple token bucket implementation
    private static class RateLimitBucket {
        private final int capacity;
        private final long windowMillis;
        private int tokens;
        private long lastRefillTime;

        public RateLimitBucket(int capacity, int timeWindow, TimeUnit unit) {
            this.capacity = capacity;
            this.windowMillis = unit.toMillis(timeWindow);
            this.tokens = capacity;
            this.lastRefillTime = System.currentTimeMillis();
        }

        public synchronized boolean tryConsume() {
            refill();
            if (tokens > 0) {
                tokens--;
                return true;
            }
            return false;
        }

        private void refill() {
            long now = System.currentTimeMillis();
            if (now - lastRefillTime >= windowMillis) {
                tokens = capacity;
                lastRefillTime = now;
            }
        }

        public int getSecondsUntilReset() {
            long now = System.currentTimeMillis();
            long millisUntilReset = windowMillis - (now - lastRefillTime);
            return (int) (millisUntilReset / 1000) + 1;
        }
    }
}