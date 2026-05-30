package io.tsm.admin.controller;

import io.tsm.admin.model.PolicySnapshot;
import io.tsm.admin.repository.PolicySnapshotRepository;
import io.tsm.admin.security.TsmPrincipal;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;
import java.util.UUID;

/**
 * Policy management API.
 *
 * GET  /api/policy/{workspaceId}/current   — latest snapshot
 * POST /api/policy/{workspaceId}/snapshots — create new snapshot (admin only)
 * GET  /api/policy/{workspaceId}/snapshots — list snapshot history
 */
@RestController
@RequestMapping("/api/policy")
@RequiredArgsConstructor
public class PolicyController {

    private final PolicySnapshotRepository snapshotRepo;

    @GetMapping("/{workspaceId}/current")
    @PreAuthorize("hasAnyRole('ADMIN', 'SECURITY_ANALYST', 'OPERATOR')")
    public ResponseEntity<PolicySnapshot> getCurrent(
            @PathVariable UUID workspaceId,
            @AuthenticationPrincipal TsmPrincipal principal) {

        return snapshotRepo.findLatestByWorkspace(workspaceId)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping("/{workspaceId}/snapshots")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<PolicySnapshot> createSnapshot(
            @PathVariable UUID workspaceId,
            @AuthenticationPrincipal TsmPrincipal principal,
            @RequestBody @Valid SnapshotRequest body) {

        // Determine next version number
        long nextVersion = snapshotRepo.findLatestByWorkspace(workspaceId)
                .map(s -> s.getVersion() + 1)
                .orElse(1L);

        PolicySnapshot snap = new PolicySnapshot();
        snap.setWorkspaceId(workspaceId);
        snap.setVersion(nextVersion);
        snap.setRulesJson(body.rulesJson());
        snap.setCreatedBy(UUID.fromString(principal.userId()));

        PolicySnapshot saved = snapshotRepo.save(snap);
        return ResponseEntity.status(HttpStatus.CREATED).body(saved);
    }

    /**
     * Request body for creating a new policy snapshot.
     * rulesJson must be a valid JSON array of rule objects.
     */
    public record SnapshotRequest(@NotNull String rulesJson) {}
}
