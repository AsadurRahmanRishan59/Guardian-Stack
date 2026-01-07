package com.rishan.guardianstack.auth.repository;

import com.rishan.guardianstack.auth.model.AuthAuditLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface AuthAuditLogRepository extends JpaRepository<AuthAuditLog, Long> {

    List<AuthAuditLog> findByUserEmailOrderByTimestampDesc(String email);

    List<AuthAuditLog> findByUserIdOrderByTimestampDesc(Long userId);

    List<AuthAuditLog> findByEventTypeOrderByTimestampDesc(String eventType);

    @Modifying
    @Query("DELETE FROM AuthAuditLog a WHERE a.timestamp < :cutoffDate")
    int deleteOldLogs(LocalDateTime cutoffDate);
}