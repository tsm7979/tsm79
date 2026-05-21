package io.tsm.admin.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

/**
 * Extracts and validates the Bearer JWT from every request.
 * Sets a fully authenticated principal in the SecurityContext on success.
 * Silent no-op on missing/invalid token — downstream security config decides
 * which endpoints require authentication.
 */
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest  request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain         filterChain
    ) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        final String token = authHeader.substring(7);
        try {
            Claims claims = jwtService.validateToken(token);

            // Extract roles claim: stored as List<String> by Jackson/JJWT
            @SuppressWarnings("unchecked")
            List<String> roles = (List<String>) claims.get("roles", List.class);
            List<SimpleGrantedAuthority> authorities = roles == null
                ? List.of()
                : roles.stream().map(r -> new SimpleGrantedAuthority("ROLE_" + r.toUpperCase())).toList();

            TsmPrincipal principal = new TsmPrincipal(
                claims.getSubject(),
                (String) claims.get("org"),
                roles == null ? new String[0] : roles.toArray(String[]::new)
            );

            UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                principal, null, authorities);
            SecurityContextHolder.getContext().setAuthentication(auth);

        } catch (JwtException e) {
            // Invalid token — leave SecurityContext empty; endpoint security decides
        }

        filterChain.doFilter(request, response);
    }
}
