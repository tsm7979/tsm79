package io.tsm.admin.repository;

import io.tsm.admin.model.PolicySnapshot;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface PolicySnapshotRepository extends JpaRepository<PolicySnapshot, UUID> {

    @Query("SELECT p FROM PolicySnapshot p WHERE p.workspaceId = :wsId ORDER BY p.version DESC LIMIT 1")
    Optional<PolicySnapshot> findLatestByWorkspace(@Param("wsId") UUID workspaceId);

    boolean existsByWorkspaceIdAndVersion(UUID workspaceId, Long version);
}
