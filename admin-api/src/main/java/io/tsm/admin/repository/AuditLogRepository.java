package io.tsm.admin.repository;

import io.tsm.admin.model.AuditLogEntry;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.UUID;

@Repository
public interface AuditLogRepository extends JpaRepository<AuditLogEntry, Long> {

    @Query("""
        SELECT a FROM AuditLogEntry a
        WHERE a.orgId = :orgId
          AND (:workspaceId IS NULL OR a.workspaceId = :workspaceId)
          AND a.ts >= :from
          AND a.ts <= :to
          AND (:action IS NULL OR a.action = :action)
          AND (:minRisk IS NULL OR a.riskScore >= :minRisk)
        ORDER BY a.ts DESC
        """)
    Page<AuditLogEntry> queryAuditLog(
        @Param("orgId")        UUID orgId,
        @Param("workspaceId")  UUID workspaceId,
        @Param("from")         Instant from,
        @Param("to")           Instant to,
        @Param("action")       String action,
        @Param("minRisk")      Double minRisk,
        Pageable pageable
    );

    @Query("""
        SELECT COUNT(a) FROM AuditLogEntry a
        WHERE a.orgId = :orgId
          AND a.workspaceId = :workspaceId
          AND a.ts >= :from
        """)
    long countSince(
        @Param("orgId")       UUID orgId,
        @Param("workspaceId") UUID workspaceId,
        @Param("from")        Instant from
    );

    @Query("""
        SELECT COUNT(a) FROM AuditLogEntry a
        WHERE a.orgId = :orgId
          AND a.workspaceId = :workspaceId
          AND a.action = 'block'
          AND a.ts >= :from
        """)
    long countBlocksSince(
        @Param("orgId")       UUID orgId,
        @Param("workspaceId") UUID workspaceId,
        @Param("from")        Instant from
    );
}
