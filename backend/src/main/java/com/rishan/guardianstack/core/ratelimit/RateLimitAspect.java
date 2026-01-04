
package com.rishan.guardianstack.core.ratelimit;

import com.rishan.guardianstack.core.exception.RateLimitExceededException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.lang.reflect.Method;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

@Aspect
@Component
@Slf4j
@RequiredArgsConstructor
public class RateLimitAspect {

    private final Map<String, RateLimitBucket> buckets = new ConcurrentHashMap<>();

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
            log.warn("Rate limit exceeded for key: {}", key);
            throw new RateLimitExceededException(
                    String.format("Too many requests. Please try again in %d seconds.", retryAfter)

            );
        }

        return joinPoint.proceed();
    }

    private String generateKey(ProceedingJoinPoint joinPoint, RateLimited rateLimited) {
        HttpServletRequest request = ((ServletRequestAttributes)
                RequestContextHolder.currentRequestAttributes()).getRequest();

        String ip = getClientIp(request);
        String method = joinPoint.getSignature().getName();

        // If custom key is provided, use it
        if (!rateLimited.key().isEmpty()) {
            return String.format("%s:%s:%s", method, rateLimited.key(), ip);
        }

        // Default: method + IP
        return String.format("%s:%s", method, ip);
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