package com.rishan.guardianstack.core.logging;

import org.jspecify.annotations.NonNull;
import org.slf4j.MDC;
import org.springframework.core.task.TaskDecorator;

import java.util.Map;

public class MdcTaskDecorator implements TaskDecorator {
    @Override
    @NonNull
    public Runnable decorate(@NonNull Runnable runnable) {
        // Capture context from the parent thread
        AuditContext.AuditMetadata context = AuditContext.get();
        Map<String, String> mdcContext = MDC.getCopyOfContextMap();

        return () -> {
            try {
                // Restore context on the child (async) thread
                if (context != null) AuditContext.set(context);
                // Explicitly check for null mdcContext
                if (mdcContext != null) {
                    MDC.setContextMap(mdcContext);
                } else {
                    MDC.clear();
                }
                runnable.run();
            } finally {
                // Always clear to prevent thread pollution
                AuditContext.clear();
            }
        };
    }
}