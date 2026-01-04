package com.rishan.guardianstack.core.ratelimit;

import java.lang.annotation.*;
import java.util.concurrent.TimeUnit;

// Annotation
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface RateLimited {
    int maxAttempts() default 5;
    int timeWindow() default 15;
    TimeUnit unit() default TimeUnit.MINUTES;
    String key() default ""; // SpEL expression for custom key
}