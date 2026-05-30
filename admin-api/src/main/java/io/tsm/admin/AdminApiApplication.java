package io.tsm.admin;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

/**
 * TSM Enterprise Admin API — Spring Boot entry point.
 *
 * Provides authenticated REST endpoints for:
 *   - Organization and workspace management
 *   - RBAC (users, roles, role assignments)
 *   - API key lifecycle (issue, rotate, revoke)
 *   - Audit log query and export
 *   - Policy management (rules, snapshots, signing)
 *   - Node registry and health
 *   - Alert rule configuration
 */
@SpringBootApplication
@EnableJpaAuditing
public class AdminApiApplication {
    public static void main(String[] args) {
        SpringApplication.run(AdminApiApplication.class, args);
    }
}
