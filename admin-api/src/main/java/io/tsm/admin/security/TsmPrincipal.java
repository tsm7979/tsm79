package io.tsm.admin.security;

import java.util.Arrays;

/**
 * Authenticated TSM admin principal extracted from a validated JWT.
 * Immutable — never mutate after construction.
 */
public record TsmPrincipal(String userId, String orgId, String[] roles) {

    public boolean hasRole(String role) {
        return Arrays.asList(roles).contains(role);
    }

    public boolean isAdmin() {
        return hasRole("admin");
    }

    public boolean isSecurityAnalyst() {
        return hasRole("security-analyst") || isAdmin();
    }
}
