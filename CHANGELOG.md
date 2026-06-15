# Changelog

All notable changes to the VWH project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-03-05

### Added

#### vwh-core (Shared Library)

- **V2 Format (256 bytes fixed)**: Complete rewrite supporting dual signatures and detached notes
- Dual signature model: Author signature (103 bytes coverage) + Seal signature (192 bytes coverage)
- Note hash field: BLAKE3 hash of detached `.vwh.note` file
- `ArtifactVersion` enum for clean v1/v2 separation
- `ArtifactBuilder::new_v2()` for creating v2 artifacts with note hash
- `seal_signing_bytes()` for seal signature coverage calculation
- `seal_fingerprint()` to retrieve seal key fingerprint from v2 artifacts
- `has_note_hash()` to detect presence of note in v2 artifacts
- `with_seal()` and `without_seal_signature()` for v2 seal management
- Backward compatibility: v1 artifacts (128 bytes) remain fully supported

#### vwh (Public Inspector)

- V2 artifact inspection with dual signature verification
- Separate display of author key and seal key for v2 artifacts
- Note file verification: checks for `.vwh.note` presence and BLAKE3 hash match
- Versioned registry paths: `/v1/` for v1 artifacts, `/v2/` for v2 artifacts
- Enhanced state display: differentiates v1 sealed vs v2 dual-signed
- Note integrity warnings when hash is present but file is missing
- Seal signature verification separate from author signature

### Changed

#### vwh-core

- `Artifact` struct now supports both v1 and v2 formats in unified structure
- `from_bytes()` auto-detects v1 (128 bytes) vs v2 (256 bytes) based on size and version field
- `is_sealed()` behavior differs: v1 checks FLAGS bit, v2 checks seal_signature presence
- `author_signing_bytes()` returns different byte counts: v1 (63 bytes) vs v2 (103 bytes)
- Version field changed from `u16` to `ArtifactVersion` enum for type safety

#### vwh (Public Inspector)

- Registry fetching now uses versioned paths based on artifact version
- Artifact information display adapts to v1 vs v2 format
- Cryptographic verification section now handles dual signatures for v2

### Breaking Changes

- **Format size**: V2 artifacts are 256 bytes (v1 was 128 bytes)
- **Registry paths**: Now versioned as `/v1/` and `/v2/` instead of root-level files
- **API changes**: `Artifact.version` is now `ArtifactVersion` enum, not raw `u16`
- **Signature field**: Renamed from `signature` to `author_signature` for clarity
- **V2 requirements**: Note file (`.vwh.note`) required for proper v2 artifacts

### Migration Guide

#### For V1 Artifacts
- No changes needed - v1 artifacts (128 bytes) continue to work perfectly
- Inspector automatically detects and handles v1 format
- Existing v1 workflows unchanged

#### For Registry Hosts
- Update registry structure to include version subdirectories:
  ```
  /vwh-registry/
    v1/
      keys.json
      ledger.json
    v2/
      keys.json
      ledger.json
  ```

#### For V2 Adoption
- Use `ArtifactBuilder::new_v2(intent, pubkey, note_hash)` instead of `new_v1()`
- Create `.vwh.note` file alongside artifact
- Compute BLAKE3 hash of note content for note_hash field
- Use seal signature for finalization instead of FLAGS bit
- Both author and seal keys needed for full v2 workflow

### Security

- Dual signature model provides ceremony separation: author vs seal authority
- Note hash binds human-readable context to cryptographic artifact
- Seal signature covers author signature, preventing signature substitution
- Note tampering detection through BLAKE3 hash verification

### Technical Details

**V2 Format Layout (256 bytes):**
```
MAGIC (4) + VERSION (2) + RESERVED_A (1) + ARTIFACT_ID (16) +
TIMESTAMP (8) + INTENT (1) + AUTHOR_PUBKEY (32) + NOTE_HASH (32) +
AUTHOR_SIGNATURE (64) + SEAL_PUBKEY (32) + SEAL_SIGNATURE (64) = 256 bytes
```

**Signature Coverage:**
- Author signs: First 103 bytes (through NOTE_HASH)
- Seal signs: First 192 bytes (through SEAL_PUBKEY, includes AUTHOR_SIGNATURE)

**Philosophy:**
V2 adds ceremony, clarity, and institutional finality without becoming a container format.
No payloads, no TLV encoding, no dynamic extensions - deterministic and bounded.

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
