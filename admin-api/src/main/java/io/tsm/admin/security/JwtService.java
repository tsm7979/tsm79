package io.tsm.admin.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

/**
 * Stateless JWT access-token service.
 *
 * Access tokens:  15-minute TTL, contains sub (user UUID), org, roles.
 * Refresh tokens: 30-day TTL, contains sub only; stored hash in admin_sessions.
 *
 * HS256 with a server-side secret (TSM_JWT_SECRET env var, min 32 bytes).
 * In production, rotate the secret via TSM_JWT_SECRET + rolling restart.
 */
@Service
public class JwtService {

    private final SecretKey key;
    private final long accessTtlMinutes;
    private final long refreshTtlDays;

    public JwtService(
            @Value("${tsm.jwt.secret}") String secret,
            @Value("${tsm.jwt.access-token-ttl-minutes:15}") long accessTtlMinutes,
            @Value("${tsm.jwt.refresh-token-ttl-days:30}") long refreshTtlDays) {
        if (secret.length() < 32) {
            throw new IllegalArgumentException(
                "TSM_JWT_SECRET must be at least 32 characters. Current length: " + secret.length());
        }
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.accessTtlMinutes = accessTtlMinutes;
        this.refreshTtlDays = refreshTtlDays;
    }

    public String generateAccessToken(UUID userId, UUID orgId, String[] roles) {
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(userId.toString())
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(accessTtlMinutes, ChronoUnit.MINUTES)))
                .claims(Map.of(
                    "org",   orgId.toString(),
                    "roles", roles
                ))
                .signWith(key, Jwts.SIG.HS256)
                .compact();
    }

    public String generateRefreshToken(UUID userId) {
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(userId.toString())
                .id(UUID.randomUUID().toString()) // jti — unique per token
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(refreshTtlDays, ChronoUnit.DAYS)))
                .signWith(key, Jwts.SIG.HS256)
                .compact();
    }

    public Claims validateToken(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public boolean isTokenValid(String token) {
        try {
            validateToken(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    public UUID extractUserId(String token) {
        return UUID.fromString(validateToken(token).getSubject());
    }

    public UUID extractOrgId(String token) {
        return UUID.fromString((String) validateToken(token).get("org"));
    }
}
