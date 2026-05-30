package io.tsm.admin.controller;

import io.tsm.admin.security.JwtService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Map;
import java.util.UUID;

/**
 * Authentication endpoints.
 *
 * POST /api/auth/login         — email/password → {accessToken, refreshToken}
 * POST /api/auth/refresh       — refreshToken   → {accessToken}
 * POST /api/auth/logout        — revoke refresh token
 *
 * Access tokens:  short-lived (15 min), stateless JWT
 * Refresh tokens: long-lived (30 days), SHA-256 hash stored in tsm.admin_sessions
 */
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final JwtService    jwtService;
    private final JdbcTemplate  jdbc;

    // ── Login ─────────────────────────────────────────────────────────────────

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody @Valid LoginRequest req) {
        // Look up user by email (within any org — email is unique globally per org)
        var rows = jdbc.queryForList(
            "SELECT id, org_id, password_hash, mfa_enabled FROM tsm.users WHERE email = ? LIMIT 1",
            req.email()
        );

        if (rows.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
        }

        var row = rows.get(0);
        String storedHash = (String) row.get("password_hash");

        // BCrypt verification — timing-safe
        if (!BCrypt.checkpw(req.password(), storedHash)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
        }

        UUID userId = (UUID) row.get("id");
        UUID orgId  = (UUID) row.get("org_id");

        // Fetch user roles
        var roleRows = jdbc.queryForList(
            """
            SELECT r.name FROM tsm.role_assignments ra
            JOIN tsm.roles r ON r.id = ra.role_id
            WHERE ra.user_id = ?
              AND (ra.expires_at IS NULL OR ra.expires_at > NOW())
            """,
            userId
        );
        String[] roles = roleRows.stream()
            .map(r -> (String) r.get("name"))
            .toArray(String[]::new);

        String accessToken  = jwtService.generateAccessToken(userId, orgId, roles);
        String refreshToken = jwtService.generateRefreshToken(userId);

        // Store SHA-256(refreshToken) in admin_sessions
        String tokenHash = sha256Hex(refreshToken);
        jdbc.update(
            """
            INSERT INTO tsm.admin_sessions (user_id, token_hash, ip_address)
            VALUES (?, ?, ?::inet)
            """,
            userId, tokenHash, "0.0.0.0" // real IP injected via HttpServletRequest in production
        );

        return ResponseEntity.ok(Map.of(
            "accessToken",  accessToken,
            "refreshToken", refreshToken,
            "tokenType",    "Bearer",
            "expiresIn",    "900"
        ));
    }

    // ── Refresh ───────────────────────────────────────────────────────────────

    @PostMapping("/refresh")
    public ResponseEntity<Map<String, String>> refresh(@RequestBody @Valid RefreshRequest req) {
        if (!jwtService.isTokenValid(req.refreshToken())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid or expired refresh token");
        }

        String tokenHash = sha256Hex(req.refreshToken());
        var rows = jdbc.queryForList(
            """
            SELECT s.user_id, u.org_id FROM tsm.admin_sessions s
            JOIN tsm.users u ON u.id = s.user_id
            WHERE s.token_hash = ?
              AND s.revoked_at IS NULL
              AND s.expires_at > NOW()
            LIMIT 1
            """,
            tokenHash
        );

        if (rows.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Refresh token not found or revoked");
        }

        UUID userId = (UUID) rows.get(0).get("user_id");
        UUID orgId  = (UUID) rows.get(0).get("org_id");

        // Touch last_used_at
        jdbc.update("UPDATE tsm.admin_sessions SET last_used_at = NOW() WHERE token_hash = ?", tokenHash);

        var roleRows = jdbc.queryForList(
            "SELECT r.name FROM tsm.role_assignments ra JOIN tsm.roles r ON r.id = ra.role_id WHERE ra.user_id = ?",
            userId
        );
        String[] roles = roleRows.stream().map(r -> (String) r.get("name")).toArray(String[]::new);

        String newAccessToken = jwtService.generateAccessToken(userId, orgId, roles);
        return ResponseEntity.ok(Map.of("accessToken", newAccessToken, "tokenType", "Bearer", "expiresIn", "900"));
    }

    // ── Logout ────────────────────────────────────────────────────────────────

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestBody @Valid RefreshRequest req) {
        String tokenHash = sha256Hex(req.refreshToken());
        jdbc.update("UPDATE tsm.admin_sessions SET revoked_at = NOW() WHERE token_hash = ?", tokenHash);
        return ResponseEntity.noContent().build();
    }

    // ── Request records ───────────────────────────────────────────────────────

    public record LoginRequest(
        @NotBlank @Email String email,
        @NotBlank         String password
    ) {}

    public record RefreshRequest(@NotBlank String refreshToken) {}

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static String sha256Hex(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
