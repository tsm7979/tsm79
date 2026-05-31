# Rust toolchain policy

This workspace pins the Rust toolchain via [`rust-toolchain.toml`](../rust-toolchain.toml) at the repo root.

## Current pin

| Channel | Why |
|---|---|
| **`1.94.0`** | Last known-good stable before the rustc 1.95.0 ICE on the dataplane crate. See [issue #36](https://github.com/tsm7979/tsm79/issues/36). |

## How the pin works

[`rustup`](https://rustup.rs/) reads `rust-toolchain.toml` automatically. The first time you run any `cargo` command in this workspace, rustup installs the pinned toolchain (and the listed components — `rustfmt`, `clippy`) if you don't already have it.

You do not need to run `rustup default` — the pin is per-workspace, not per-user.

## CI

The same pin file is used by GitHub Actions runners. No special CI configuration is required; `actions-rust-lang/setup-rust-toolchain` honours the workspace pin.

## Bumping the pin

1. On a feature branch, edit `rust-toolchain.toml` to the candidate channel
2. Run `cargo build --workspace` and `cargo test --workspace` to verify the candidate is green
3. Open a PR titled `chore(rust): bump pinned toolchain to <version>`
4. Reference the original blocker (the rustc 1.95.0 ICE) in the PR body
5. If the bump unblocks an upstream-tracked issue (such as [#36](https://github.com/tsm7979/tsm79/issues/36)), close the issue from the PR

## Why not "stable"?

`channel = "stable"` is the default rustup behaviour, but it lets a single contributor's machine determine the build. Pinning to an exact version makes:

- Build reproducibility a property of the repo, not the contributor
- Toolchain upgrades a deliberate, reviewable PR
- CI and local builds bit-for-bit equivalent

This is the same pattern used by every production Rust codebase we respect — `rust-analyzer`, `cargo` itself, `tokio`, `axum`, `pingora`, …

## Why not nightly?

The dataplane uses only stable-channel features. Nightly is reserved for one-off experiments in branch-only crates.
