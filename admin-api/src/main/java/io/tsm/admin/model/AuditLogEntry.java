package io.tsm.admin.model;

import jakarta.persistence.*;
import lombok.Getter;
import org.hibernate.annotations.Immutable;

import java.time.Instant;
import java.util.UUID;

/**
 * Read-only projection of tsm.audit_log.
 * The table is append-only; Spring must never attempt INSERT/UPDATE/DELETE.
 */
@Entity
@Immutable
@Table(name = "audit_log", schema = "tsm")
@Getter
public class AuditLogEntry {

    @Id
    @Column(name = "id")
    private Long id;

    @Column(name = "ts")
    private Instant ts;

    @Column(name = "org_id")
    private UUID orgId;

    @Column(name = "workspace_id")
    private UUID workspaceId;

    @Column(name = "request_id")
    private UUID requestId;

    @Column(name = "node_id")
    private String nodeId;

    @Column(name = "client_ip", columnDefinition = "inet")
    private String clientIp;

    @Column(name = "method")
    private String method;

    @Column(name = "path")
    private String path;

    @Column(name = "model")
    private String model;

    @Column(name = "upstream")
    private String upstream;

    @Column(name = "action")
    private String action;

    @Column(name = "rule_fired")
    private String ruleFired;

    @Column(name = "pii_types", columnDefinition = "text[]")
    private String[] piiTypes;

    @Column(name = "risk_score")
    private Double riskScore;

    @Column(name = "severity")
    private String severity;

    @Column(name = "streamed")
    private Boolean streamed;

    @Column(name = "redacted")
    private Boolean redacted;

    @Column(name = "latency_ms")
    private Double latencyMs;

    @Column(name = "detector_ms")
    private Double detectorMs;

    @Column(name = "upstream_ms")
    private Double upstreamMs;

    @Column(name = "prompt_tokens")
    private Integer promptTokens;

    @Column(name = "completion_tokens")
    private Integer completionTokens;

    @Column(name = "traceparent")
    private String traceparent;

    @Column(name = "tags", columnDefinition = "jsonb")
    private String tags;
}
