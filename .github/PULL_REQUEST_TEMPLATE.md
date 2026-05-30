<!--
Thanks for sending a PR to TSM79. Please fill in the sections below so we can
review efficiently. If your change is trivial (typo, doc fix), feel free to
delete the inapplicable sections.
-->

## Summary

<!-- 1-3 sentences. What does this PR do? Why? -->

## Motivation

<!--
Link to the issue or discussion this PR addresses.
- Closes #<issue>
- Refs #<issue>
- Discussion: <url>
-->

## Scope of Change

- [ ] `dataplane/` (Rust hot path)
- [ ] `detector/` (Python ML)
- [ ] `control-plane/` (Go)
- [ ] `threat-intel/` (Go)
- [ ] `overlay-node/` (Go libp2p)
- [ ] `admin-api/` (Java Spring Boot)
- [ ] `policy-lsp/` (C# .NET)
- [ ] `edge/` (C++ wasmtime)
- [ ] `ebpf/` / `ebpf-loader/` / `ebpf-loader-c/` (eBPF / loader)
- [ ] `dashboard/` (Next.js)
- [ ] `extension/` (MV3)
- [ ] `landing*/` (static)
- [ ] `proto/` (gRPC contract)
- [ ] `observability/` (ClickHouse / Prometheus)
- [ ] `deploy/` (Postgres migrations / nginx)
- [ ] `docs/` (technical deep-dives)
- [ ] `tests/` (cross-component E2E)
- [ ] `.github/` (CI / workflows / templates)

## Test Plan

<!--
Required for non-doc changes. Bullet-list what you verified and how.
-->

- [ ] Unit tests pass locally (`cargo test` / `pytest` / `go test` / `pnpm test` as applicable)
- [ ] Linter / formatter clean (`clippy` / `ruff` / `gofmt` / `eslint` as applicable)
- [ ] Coverage on new code ≥ 80%
- [ ] Manually reproduced the bug (for fixes) and confirmed the fix resolves it
- [ ] Enterprise compose stack still starts (`docker compose -f docker-compose.enterprise.yml up -d` is green)
- [ ] No new dependencies — or new dependencies are justified in the PR body

## Reverse-Compatibility

<!--
For dataplane HTTP, gRPC contract, sovereign-overlay signing-byte, audit-ledger
schema, or any other operator-visible surface — describe the impact.
-->

- [ ] No breaking change to the dataplane HTTP contract
- [ ] No breaking change to the dataplane↔detector gRPC contract
- [ ] No breaking change to the sovereign-overlay `NameRecord` signing bytes
- [ ] No breaking change to the audit ledger schema
- [ ] Breaking change — migration plan documented below

<!--
If this IS a breaking change, write the migration plan here. Operators reading
release notes must be able to follow this without further questions.
-->

## Security Implications

<!--
If this touches authentication, audit, detection rules, sovereign-overlay
signing, the Wasm sandbox, or anything in the SECURITY.md scope, describe
the threat model implications here.
-->

- [ ] No security implications
- [ ] Security-sensitive — see notes below
- [ ] Security review requested

## Screenshots / Demos

<!-- For UI changes (dashboard, landing, extension). -->

## Checklist

- [ ] I have read [CONTRIBUTING.md](../CONTRIBUTING.md)
- [ ] I have signed off on the [Code of Conduct](../CODE_OF_CONDUCT.md)
- [ ] My commits follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)
- [ ] My PR title is suitable for the squash commit message (this will land on `main`)
