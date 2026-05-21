package io.tsm.admin.controller;

import io.tsm.admin.security.TsmPrincipal;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Cluster node registry API.
 *
 * GET  /api/nodes              — list all nodes for org (with health status)
 * GET  /api/nodes/{id}         — node detail + last 24h health history
 * POST /api/nodes/{id}/drain   — mark node unhealthy (admin only; triggers LB removal)
 */
@RestController
@RequestMapping("/api/nodes")
@RequiredArgsConstructor
public class NodeController {

    private final JdbcTemplate jdbc;

    @GetMapping
    @PreAuthorize("hasAnyRole('ADMIN', 'OPERATOR', 'VIEWER')")
    public ResponseEntity<List<Map<String, Object>>> listNodes(
            @AuthenticationPrincipal TsmPrincipal principal) {
        List<Map<String, Object>> nodes = jdbc.queryForList(
            """
            SELECT n.id, n.role, n.addr, n.healthy, n.consecutive_fails,
                   n.policy_version, n.version_string, n.region, n.zone,
                   n.last_seen_at, n.labels,
                   EXTRACT(EPOCH FROM (NOW() - n.last_seen_at))::INT AS seconds_since_seen
            FROM tsm.nodes n
            WHERE n.org_id = ?::uuid
            ORDER BY n.role, n.region, n.id
            """,
            principal.orgId()
        );
        return ResponseEntity.ok(nodes);
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('ADMIN', 'OPERATOR')")
    public ResponseEntity<Map<String, Object>> getNode(
            @PathVariable String id,
            @AuthenticationPrincipal TsmPrincipal principal) {

        var rows = jdbc.queryForList(
            "SELECT * FROM tsm.nodes WHERE id = ? AND org_id = ?::uuid",
            id, principal.orgId()
        );
        if (rows.isEmpty()) return ResponseEntity.notFound().build();

        Map<String, Object> node = rows.get(0);

        // Attach last 24h health samples
        List<Map<String, Object>> history = jdbc.queryForList(
            """
            SELECT ts, healthy, latency_ms, status_code, error_msg
            FROM tsm.node_health_history
            WHERE node_id = ? AND ts > NOW() - INTERVAL '24 hours'
            ORDER BY ts DESC
            LIMIT 500
            """,
            id
        );
        node.put("healthHistory", history);

        return ResponseEntity.ok(node);
    }

    @PostMapping("/{id}/drain")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> drainNode(
            @PathVariable String id,
            @AuthenticationPrincipal TsmPrincipal principal) {

        int updated = jdbc.update(
            """
            UPDATE tsm.nodes SET healthy = FALSE, consecutive_fails = 99
            WHERE id = ? AND org_id = ?::uuid
            """,
            id, principal.orgId()
        );

        if (updated == 0) return ResponseEntity.notFound().build();
        return ResponseEntity.ok(Map.of("nodeId", id, "status", "drained"));
    }
}
