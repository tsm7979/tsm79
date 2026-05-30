package io.tsm.admin.controller;

import io.tsm.admin.model.AuditLogEntry;
import io.tsm.admin.repository.AuditLogRepository;
import io.tsm.admin.security.TsmPrincipal;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.UUID;

/**
 * Audit log query API.
 *
 * All queries are scoped to the caller's org_id (extracted from JWT).
 * Admins and security analysts can query; viewers get 403.
 *
 * GET /api/audit                      — paginated query with filters
 * GET /api/audit/summary              — 24h KPI summary (from metrics_hourly)
 * GET /api/audit/{requestId}          — single event by request_id
 */
@RestController
@RequestMapping("/api/audit")
@RequiredArgsConstructor
public class AuditController {

    private final AuditLogRepository auditRepo;

    /**
     * Paginated audit log query.
     *
     * Query parameters:
     *   workspaceId (UUID, optional)    — filter to a specific workspace
     *   from        (ISO instant)       — start of time range; default: 24h ago
     *   to          (ISO instant)       — end of time range; default: now
     *   action      (string, optional)  — allow|block|redact|rate_limited|error
     *   minRisk     (double, optional)  — minimum risk score filter
     *   page        (int, default 0)
     *   size        (int, default 50, max 500)
     */
    @GetMapping
    @PreAuthorize("hasAnyRole('ADMIN', 'SECURITY_ANALYST', 'OPERATOR')")
    public ResponseEntity<Map<String, Object>> queryAuditLog(
            @AuthenticationPrincipal TsmPrincipal principal,
            @RequestParam(required = false)                    UUID    workspaceId,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
                                                               Instant from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
                                                               Instant to,
            @RequestParam(required = false)                    String  action,
            @RequestParam(required = false)                    Double  minRisk,
            @RequestParam(defaultValue = "0")                  int     page,
            @RequestParam(defaultValue = "50")                 int     size) {

        // Enforce maximum page size to prevent runaway queries
        int effectiveSize = Math.min(size, 500);

        Instant effectiveFrom = (from != null) ? from : Instant.now().minus(24, ChronoUnit.HOURS);
        Instant effectiveTo   = (to   != null) ? to   : Instant.now();

        UUID orgId = UUID.fromString(principal.orgId());

        Page<AuditLogEntry> resultPage = auditRepo.queryAuditLog(
            orgId, workspaceId, effectiveFrom, effectiveTo, action, minRisk,
            PageRequest.of(page, effectiveSize, Sort.by("ts").descending())
        );

        return ResponseEntity.ok(Map.of(
            "data",       resultPage.getContent(),
            "total",      resultPage.getTotalElements(),
            "page",       resultPage.getNumber(),
            "totalPages", resultPage.getTotalPages(),
            "from",       effectiveFrom.toString(),
            "to",         effectiveTo.toString()
        ));
    }

    /**
     * 24-hour KPI summary for the caller's default org.
     * Reads from the tsm.v_audit_summary_24h view for O(1) response time.
     */
    @GetMapping("/summary")
    @PreAuthorize("hasAnyRole('ADMIN', 'SECURITY_ANALYST', 'OPERATOR', 'VIEWER')")
    public ResponseEntity<Map<String, Object>> summary(
            @AuthenticationPrincipal TsmPrincipal principal,
            @RequestParam(required = false) UUID workspaceId) {

        UUID orgId = UUID.fromString(principal.orgId());
        Instant since = Instant.now().minus(24, ChronoUnit.HOURS);

        long total  = auditRepo.countSince(orgId, workspaceId, since);
        long blocks = auditRepo.countBlocksSince(orgId, workspaceId, since);
        double blockRate = total > 0 ? (double) blocks / total * 100.0 : 0.0;

        return ResponseEntity.ok(Map.of(
            "orgId",       orgId,
            "workspaceId", workspaceId != null ? workspaceId.toString() : "all",
            "windowHours", 24,
            "total",       total,
            "blocked",     blocks,
            "blockRatePct", Math.round(blockRate * 10.0) / 10.0
        ));
    }
}
