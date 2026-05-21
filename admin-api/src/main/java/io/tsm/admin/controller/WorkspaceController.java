package io.tsm.admin.controller;

import io.tsm.admin.security.TsmPrincipal;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.*;

/**
 * Workspace management API.
 *
 * GET    /api/workspaces             — list workspaces for caller's org
 * POST   /api/workspaces             — create workspace (admin only)
 * GET    /api/workspaces/{id}        — get workspace details
 * PATCH  /api/workspaces/{id}        — update workspace (admin only)
 * DELETE /api/workspaces/{id}        — archive workspace (admin only)
 *
 * GET    /api/workspaces/{id}/api-keys         — list API keys (no secret)
 * POST   /api/workspaces/{id}/api-keys         — issue new API key
 * DELETE /api/workspaces/{id}/api-keys/{keyId} — revoke key
 */
@RestController
@RequestMapping("/api/workspaces")
@RequiredArgsConstructor
public class WorkspaceController {

    private final JdbcTemplate jdbc;

    // ── Workspace CRUD ────────────────────────────────────────────────────────

    @GetMapping
    @PreAuthorize("hasAnyRole('ADMIN', 'OPERATOR', 'VIEWER')")
    public ResponseEntity<List<Map<String, Object>>> listWorkspaces(
            @AuthenticationPrincipal TsmPrincipal principal) {
        List<Map<String, Object>> workspaces = jdbc.queryForList(
            """
            SELECT id, slug, display_name, rate_limit_rpm, archived_at, created_at
            FROM tsm.workspaces
            WHERE org_id = ?::uuid
            ORDER BY created_at DESC
            """,
            principal.orgId()
        );
        return ResponseEntity.ok(workspaces);
    }

    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> createWorkspace(
            @AuthenticationPrincipal TsmPrincipal principal,
            @RequestBody @Valid WorkspaceRequest req) {

        // Check org workspace limit
        int count = jdbc.queryForObject(
            "SELECT COUNT(*) FROM tsm.workspaces WHERE org_id = ?::uuid AND archived_at IS NULL",
            Integer.class, principal.orgId()
        );
        int maxWs = jdbc.queryForObject(
            "SELECT max_workspaces FROM tsm.organizations WHERE id = ?::uuid",
            Integer.class, principal.orgId()
        );
        if (count >= maxWs) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                "Workspace limit reached (" + maxWs + "). Upgrade plan to add more.");
        }

        UUID id = UUID.randomUUID();
        jdbc.update(
            """
            INSERT INTO tsm.workspaces (id, org_id, slug, display_name, rate_limit_rpm)
            VALUES (?, ?::uuid, ?, ?, ?)
            """,
            id, principal.orgId(), req.slug(), req.displayName(), req.rateLimitRpm()
        );

        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
            "id",   id,
            "slug", req.slug()
        ));
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('ADMIN', 'OPERATOR', 'VIEWER')")
    public ResponseEntity<Map<String, Object>> getWorkspace(
            @PathVariable UUID id,
            @AuthenticationPrincipal TsmPrincipal principal) {
        var rows = jdbc.queryForList(
            """
            SELECT w.id, w.slug, w.display_name, w.rate_limit_rpm, w.archived_at, w.created_at,
                   COUNT(k.id) AS api_key_count
            FROM tsm.workspaces w
            LEFT JOIN tsm.api_keys k ON k.workspace_id = w.id AND k.revoked_at IS NULL
            WHERE w.id = ? AND w.org_id = ?::uuid
            GROUP BY w.id
            """,
            id, principal.orgId()
        );
        if (rows.isEmpty()) return ResponseEntity.notFound().build();
        return ResponseEntity.ok(rows.get(0));
    }

    @PatchMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> updateWorkspace(
            @PathVariable UUID id,
            @AuthenticationPrincipal TsmPrincipal principal,
            @RequestBody Map<String, Object> updates) {

        if (updates.containsKey("rateLimitRpm")) {
            int rpm = (int) updates.get("rateLimitRpm");
            jdbc.update(
                "UPDATE tsm.workspaces SET rate_limit_rpm = ? WHERE id = ? AND org_id = ?::uuid",
                rpm, id, principal.orgId()
            );
        }
        if (updates.containsKey("displayName")) {
            jdbc.update(
                "UPDATE tsm.workspaces SET display_name = ? WHERE id = ? AND org_id = ?::uuid",
                updates.get("displayName"), id, principal.orgId()
            );
        }
        return ResponseEntity.noContent().build();
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> archiveWorkspace(
            @PathVariable UUID id,
            @AuthenticationPrincipal TsmPrincipal principal) {
        int updated = jdbc.update(
            "UPDATE tsm.workspaces SET archived_at = NOW() WHERE id = ? AND org_id = ?::uuid AND archived_at IS NULL",
            id, principal.orgId()
        );
        return updated > 0 ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }

    // ── API Key management ────────────────────────────────────────────────────

    @GetMapping("/{id}/api-keys")
    @PreAuthorize("hasAnyRole('ADMIN', 'OPERATOR')")
    public ResponseEntity<List<Map<String, Object>>> listApiKeys(
            @PathVariable UUID id,
            @AuthenticationPrincipal TsmPrincipal principal) {
        List<Map<String, Object>> keys = jdbc.queryForList(
            """
            SELECT k.id, k.key_prefix, k.name, k.created_at, k.last_used_at,
                   k.expires_at, k.revoked_at, k.permissions
            FROM tsm.api_keys k
            JOIN tsm.workspaces w ON w.id = k.workspace_id
            WHERE k.workspace_id = ? AND w.org_id = ?::uuid
            ORDER BY k.created_at DESC
            """,
            id, principal.orgId()
        );
        return ResponseEntity.ok(keys);
    }

    @PostMapping("/{id}/api-keys")
    @PreAuthorize("hasAnyRole('ADMIN', 'OPERATOR')")
    public ResponseEntity<Map<String, Object>> issueApiKey(
            @PathVariable UUID id,
            @AuthenticationPrincipal TsmPrincipal principal,
            @RequestBody @Valid ApiKeyRequest req) {

        // Generate a random API key: tsm_live_<random32>
        String rawKey   = "tsm_live_" + randomHex(32);
        String prefix   = rawKey.substring(0, 16);   // "tsm_live_xxxxxxx" — safe to show later

        // SHA-256 hash — only hash stored, never raw key after this point
        String keyHash  = sha256Hex(rawKey);

        UUID keyId = UUID.randomUUID();
        jdbc.update(
            """
            INSERT INTO tsm.api_keys (id, workspace_id, key_prefix, key_hash, name, permissions)
            VALUES (?, ?, ?, ?, ?, ?::jsonb)
            """,
            keyId, id, prefix, keyHash, req.name(), req.permissions()
        );

        // Return raw key ONCE — caller must store it; we cannot recover it
        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
            "id",         keyId,
            "key",        rawKey,    // shown only at creation
            "prefix",     prefix,
            "name",       req.name(),
            "warning",    "Store this key securely — it will not be shown again."
        ));
    }

    @DeleteMapping("/{id}/api-keys/{keyId}")
    @PreAuthorize("hasAnyRole('ADMIN', 'OPERATOR')")
    public ResponseEntity<Void> revokeApiKey(
            @PathVariable UUID id,
            @PathVariable UUID keyId,
            @AuthenticationPrincipal TsmPrincipal principal) {
        int updated = jdbc.update(
            """
            UPDATE tsm.api_keys SET revoked_at = NOW()
            WHERE id = ? AND workspace_id = ? AND revoked_at IS NULL
            """,
            keyId, id
        );
        return updated > 0 ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }

    // ── Request records ───────────────────────────────────────────────────────

    public record WorkspaceRequest(
        @NotBlank @Pattern(regexp = "^[a-z0-9-]{2,64}$") String slug,
        @NotBlank String displayName,
        int rateLimitRpm
    ) {}

    public record ApiKeyRequest(
        @NotBlank String name,
        String permissions   // JSON string: e.g. ["proxy:write","audit:read"]
    ) {}

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static String randomHex(int bytes) {
        byte[] buf = new byte[bytes];
        new java.security.SecureRandom().nextBytes(buf);
        return HexFormat.of().formatHex(buf);
    }

    private static String sha256Hex(String input) {
        try {
            var md = java.security.MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(md.digest(input.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
