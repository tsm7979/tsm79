# Contributing to TSM79

Thanks for taking an interest. This is what working with us looks like.

## TL;DR

- Open an issue first for anything non-trivial. We will tell you whether it is in scope before you spend a weekend on it.
- Branch from `main`, name it `feat/<thing>`, `fix/<thing>`, or `docs/<thing>`.
- Write tests. Coverage threshold for new code is **80%**.
- Follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).
- Open a PR against `main`. The CI must be green and at least one maintainer must approve before merge.
- Read the [Code of Conduct](CODE_OF_CONDUCT.md) and the [Security Policy](SECURITY.md).

## Repository Layout

```
dataplane/         Rust — the inline AI firewall (hot path)
detector/          Python — ML detector (NER + classifier), gRPC + HTTP
control-plane/     Go — config + workspace + key store
threat-intel/      Go — IP reputation feeds
admin-api/         Java (Spring Boot) — operator REST control
policy-lsp/        C# (.NET) — policy DSL language server
edge/              C++ (wasmtime) — Wasm worker host
overlay-node/      Go (libp2p) — sovereign-overlay DHT node
ebpf-loader/       Rust — XDP/TC loader (Aya variant)
ebpf-loader-c/     C — XDP/TC loader (libbpf variant)
ebpf/              eBPF/XDP — packet-authority programs
tsm/               Python — SDK + CLI
tsm-ctl/           Rust — operator CLI
proto/             Protobufs (dataplane↔detector + dataplane↔edge gRPC)
observability/     ClickHouse schema + Rust ingestor
deploy/            Postgres migrations + nginx config
docs/              Technical deep-dives
tests/             Cross-component E2E
```

## Local Setup

Pre-requisites depend on the layer you're working on. The minimum useful set:

```bash
# Rust toolchain (dataplane, ebpf-loader, tsm-ctl)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup component add clippy rustfmt

# Python 3.12 (detector, tests)
pyenv install 3.12.7
pyenv local 3.12.7
python -m pip install --upgrade pip
pip install -e ".[detector,dev]"

# Go 1.22+ (control-plane, threat-intel, overlay-node)
# https://go.dev/dl/

# Docker + Compose v2 (enterprise stack)
# https://docs.docker.com/get-docker/

# Java 21 + Maven (admin-api)
# .NET 8 SDK (policy-lsp)
```

You do not need every toolchain to contribute — pick a layer.

### One-shot stack

```bash
cp .env.example .env       # fill in CLICKHOUSE_PASSWORD + provider keys
docker compose -f docker-compose.enterprise.yml up -d
```

Eleven services come up. Health-check probes are configured on all of them — `docker compose ps` should be green within ~60s.

## Development Workflow

### 1. Issue first

Search [open issues](https://github.com/tsm7979/tsm79/issues). If yours doesn't exist, open one with a clear title and a 3-paragraph description. Wait for a `triaged` label before opening a PR for significant changes.

Small fixes (typos, a single failing test, an obvious bug) — go straight to a PR.

### 2. Branch

```bash
git checkout -b feat/sovereign-overlay-name-rotation
```

Conventions:
- `feat/<thing>` — new feature
- `fix/<thing>` — bug fix
- `refactor/<thing>` — refactor without behaviour change
- `docs/<thing>` — docs only
- `chore/<thing>` — tooling, deps, CI, infra

### 3. Test

Coverage threshold is 80% on new code.

```bash
# Rust (dataplane, ebpf-loader, tsm-ctl)
cargo test --workspace

# Python (detector, end-to-end)
pytest

# Go (control-plane, threat-intel, overlay-node)
go test ./...

# TypeScript (only if you're contributing to companion repos)
pnpm test
```

Per-language guidance:

- **Rust**: `cargo clippy -- -D warnings` and `cargo fmt --check` before pushing
- **Python**: `ruff check .` and `black --check .` before pushing
- **Go**: `gofmt -l .` returns empty; `go vet ./...` clean
- **TypeScript**: `pnpm lint` and `pnpm typecheck` clean
- **CSS / .NET / Java / C / C++**: see component-local README if present

### 4. Commit

[Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/):

```
<type>(<scope>): <short subject>

<longer body explaining the why>
```

Types: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`, `perf`, `ci`, `build`, `style`.

Examples:

- `feat(overlay): rotate NameRecord every 24h to limit hijack window`
- `fix(dataplane): h1 parser dropped last header of every request`
- `docs(policy): document rule-priority ordering`

### 5. PR

Open against `main`. The PR template will prompt you for the right context. The CI runs:

- All language test suites
- Linters + formatters
- Security audits (`cargo audit`, `pip-audit`, `npm audit`)
- Docker build verification

Address review comments by **pushing new commits**, not rewriting history — we squash on merge.

### 6. Merge

A maintainer merges via squash. The squash commit message is the PR title + body; please write the PR carefully because that is what lands on `main`.

## What We Will Reject

- Code without tests
- Code with new dependencies that aren't justified
- Commits that mix unrelated changes (split them)
- PRs that introduce console.log, `dbg!`, or `print()` left in production code
- Hardcoded secrets, even in tests (use the `*_DEMO_FIXTURE_*` pattern — see [SECURITY.md](SECURITY.md))
- Anything that breaks reverse-compat of the dataplane HTTP contract without a migration plan

## What We Welcome

- Detection rules with high precision (low false-positive rate)
- New language adapters (a Ruby SDK? a Rust SDK? a Java SDK?)
- Performance regressions caught — and fixed
- Docs that turn implicit knowledge into explicit prose
- New `.tsm` overlay use cases
- New language SDKs (Ruby, Java, Kotlin, C#)

## Voice

Operator-facing copy — CLI, dashboard, marketing, docs — speaks in the **TSM voice**: terse, mechanical, em-dash-heavy, sovereign-agency register. Visual grammar is square corners, hairline borders, a single `#C7F23E` (`--signal`) accent per fold, mask-wipe reveals, no drop shadows, no gradients.

Words we don't write: *empower / unlock / seamless / leverage / revolutionary / AI-powered*.

## Recognition

Contributors are credited in [MAINTAINERS.md](MAINTAINERS.md) once they have landed three substantive PRs. Significant or sustained contributions are recognised in release notes.

## Questions

- Open a [discussion](https://github.com/tsm7979/tsm79/discussions) for design conversations
- Use an issue for bugs and concrete feature proposals
- For security, follow [SECURITY.md](SECURITY.md)
- General contact: <founder@thesovereignmechanica.ai>
