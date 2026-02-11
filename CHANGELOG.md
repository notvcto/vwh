# Changelog

All notable changes to the VWH project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.2] - 2026-02-11

### Changed

#### vwh (Public Inspector)

- Registry URLs now use versioned paths: `/v1/keys.json` and `/v1/ledger.json`
- Prepares infrastructure for future v2 registry at `/v2/`
- No functional changes to artifact inspection

### Migration Notes

If you host your own registry, update your paths:
- Old: `https://example.com/vwh-registry/keys.json`
- New: `https://example.com/vwh-registry/v1/keys.json`

## [1.0.1] - 2026-02-11

### Added

#### vwh (Public Inspector)

- VWH v2 format detection with graceful error message
- Clear upgrade instructions when v2 artifacts are encountered
- Forward compatibility preparation for v2.0.0 release

### Changed

- Inspector now detects v2 artifacts (256 bytes) and provides helpful upgrade guidance
- No functional changes to v1 artifact inspection

## [1.0.0] - 2026-02-10

### Added

#### vwh (Public Inspector)

- Ledger-backed verification via `ledger.json` (replaces `revocations.json`)
- Clear verdict messaging for sealed/draft vs ledger status
- Registry status now reports ledger availability and update time
- ASCII-safe output for consistent rendering across terminals

#### vwh-core (Shared Library)

- Ledger-friendly metadata handling used by `vwh` inspection flow

#### Documentation

- Updated README and SPEC for the public release
- Registry format clarified around `ledger.json`

### Changed

- Registry checks now rely on ledger status for public acknowledgment
- Output formatting standardized for release builds

### Security

- Ledger status is surfaced to detect tampering when local flags disagree with public records

## [0.1.0] - 2026-02-08

### Added

#### vwh-core (Shared Library)

- Binary format parser for `.vwh` artifacts (v1 format)
- Ed25519 signature creation and verification
- BLAKE3 fingerprint calculation
- Intent enum (LAB, OWNED-INFRA, AUTH-REDTEAM, BLUE-REMEDIATION, RESEARCH)
- Artifact ID generation (128-bit random)
- Complete error handling with descriptive messages
- Comprehensive unit tests for crypto and format parsing

#### vwh-author (Private Authoring Tool)

- `key init` - Ed25519 keypair generation with passphrase protection
  - Argon2id key derivation (64 MiB, 3 iterations)
  - ChaCha20-Poly1305 encryption
  - Secure passphrase input with confirmation
  - Config storage at `~/.config/vwh-author/`
- `key show` - Display public key and fingerprint
- `create` - Generate signed artifacts
  - Explicit intent requirement (no default)
  - Optional project and system metadata
  - Required reason/note field
  - File overwrite protection
  - Cryptographic signing with author identity
- Clean CLI with clap argument parsing
- Comprehensive error messages

#### vwh (Public Inspector)

- `inspect` - Artifact verification and display
  - Binary format parsing
  - Ed25519 signature verification
  - Optional registry checking (keys.json, revocations.json)
  - Graceful offline mode
  - Clear verification status display
- Registry integration:
  - HTTP client with 5-second timeout
  - Key status checking
  - Artifact revocation checking
  - Fallback when registry unavailable
- Clean output formatting with status indicators

#### Documentation

- Comprehensive README with build instructions
- SPEC.md with complete system specification
- In-code documentation and comments
- Example generation instructions

#### Build System

- Rust workspace configuration
- Shared dependency management
- Release and debug build support
- Cross-crate dependency resolution

### Security

- All private keys encrypted at rest
- Passphrase-based key derivation (Argon2id)
- No plaintext secrets on disk
- Secure memory handling with zeroize
- Offline-capable verification

### Format Specification

- Magic bytes: `VWH\0`
- Version: 1
- Minimum size: 128 bytes
- Fixed field layout (see SPEC.md)
- Signature over all fields except signature itself

## [Unreleased]

### Planned for Future Milestones

- Key rotation workflow
- Key revocation
- Artifact revocation CLI
- Encrypted payload support
- Private artifact registry
- File integrity hash tracking
- Export commands for registry updates
- Hardware token support (YubiKey)
