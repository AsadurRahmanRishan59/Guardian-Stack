package com.rishan.guardianstack.core.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;

/**
 * Enables AspectJ support for @Aspect annotations
 * Required for rate limiting and other AOP features
 */
@Configuration
@EnableAspectJAutoProxy
public class AspectJConfig {
    // AOP configuration
    // Rate limiting aspect will be automatically picked up
}