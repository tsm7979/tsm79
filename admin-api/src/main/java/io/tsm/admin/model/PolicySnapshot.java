package io.tsm.admin.model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "policy_snapshots", schema = "tsm")
@EntityListeners(AuditingEntityListener.class)
@Getter @Setter
public class PolicySnapshot {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id;

    @Column(name = "workspace_id")
    private UUID workspaceId;

    @Column(name = "version", nullable = false, unique = true)
    private Long version;

    @Column(name = "rules_json", columnDefinition = "jsonb", nullable = false)
    private String rulesJson;

    @Column(name = "signature")
    private String signature;

    @Column(name = "pub_key_id")
    private UUID pubKeyId;

    @Column(name = "created_by")
    private UUID createdBy;

    @CreatedDate
    @Column(name = "created_at", updatable = false)
    private Instant createdAt;
}
