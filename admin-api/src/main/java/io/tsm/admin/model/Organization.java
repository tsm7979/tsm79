package io.tsm.admin.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "organizations", schema = "tsm")
@EntityListeners(AuditingEntityListener.class)
@Getter @Setter
public class Organization {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    @NotBlank
    @Pattern(regexp = "^[a-z0-9-]{2,64}$", message = "slug must be lowercase alphanumeric with hyphens")
    @Column(unique = true, nullable = false)
    private String slug;

    @NotBlank
    @Column(name = "display_name", nullable = false)
    private String displayName;

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private Plan plan = Plan.STARTER;

    @Column(name = "max_workspaces", nullable = false)
    private int maxWorkspaces = 3;

    @Column(name = "max_api_keys", nullable = false)
    private int maxApiKeys = 10;

    @Column(name = "max_rpm", nullable = false)
    private int maxRpm = 1000;

    @CreatedDate
    @Column(name = "created_at", updatable = false)
    private Instant createdAt;

    @Column(name = "suspended_at")
    private Instant suspendedAt;

    @Column(columnDefinition = "jsonb", nullable = false)
    private String metadata = "{}";

    public boolean isSuspended() {
        return suspendedAt != null;
    }

    public enum Plan {
        STARTER, PRO, ENTERPRISE
    }
}
