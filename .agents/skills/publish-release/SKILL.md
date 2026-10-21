---
name: publish-release
description: Multi-step runbook for releasing Uncrowned King versions with atomic manifest synchronization, Keep-a-Changelog formatting, GPG signing, and release CI verification.
---

# Uncrowned King Release Runbook

Follow this workflow whenever cutting a new release (e.g., `v1.0.2` or `v1.1.0`).

## 1. Pre-Release Verification Gates
Before bumping any versions, verify the entire test suite and linters pass:
```bash
cargo fmt --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

## 2. Multi-File Version Synchronization
Update the version string across all required files in the workspace:
1. `Cargo.toml`: Update `[workspace.package] version = "X.Y.Z"`.
2. `Cargo.lock`: Run `cargo check --workspace` to propagate the version to all crate lock entries.
3. `deploy/helm/uncrowned-king/Chart.yaml`: Update `version: X.Y.Z` and `appVersion: "vX.Y.Z"`.
4. `deploy/helm/uncrowned-king/values.yaml`: Update `tag: "vX.Y.Z"` for both server and client images.
5. `deploy/kubernetes/uncrowned-king-server.yaml`: Update container image tag to `vX.Y.Z`.

## 3. Changelog Documentation
Update `CHANGELOG.md` following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/):
1. Insert `## [X.Y.Z] - YYYY-MM-DD` beneath `## [Unreleased]`.
2. Group changes under standard headers: `### Added`, `### Changed`, `### Security`, `### Fixed`.
3. Update compare links at the bottom:
   ```markdown
   [Unreleased]: https://github.com/HappyLeslieAlexander/Uncrowned-King/compare/vX.Y.Z...HEAD
   [X.Y.Z]: https://github.com/HappyLeslieAlexander/Uncrowned-King/compare/vPREV...vX.Y.Z
   ```

## 4. GPG-Signed Commit & Tag
All release commits and tags must be cryptographically signed with the project GPG key:
```bash
git add Cargo.toml Cargo.lock deploy/ CHANGELOG.md
git commit -S -m "release: bump version to X.Y.Z"
git tag -s vX.Y.Z -m "Release vX.Y.Z: <brief description>"
```
Verify the signatures before pushing:
```bash
git verify-commit HEAD
git tag -v vX.Y.Z
```

## 5. Push & Automated CI Release
Push both the branch commit and the signed tag:
```bash
git push origin main
git push origin vX.Y.Z
```
Monitor the GitHub Actions release workflow:
```bash
gh run list --limit 3
gh release view vX.Y.Z
```
Ensure that CycloneDX SBOM, cross-platform binaries, and container images are generated and attached.
