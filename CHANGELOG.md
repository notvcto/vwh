# Changelog

All notable changes to VWH are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) — Versioning: [SemVer](https://semver.org/spec/v2.0.0.html)

---

## [2.0.2] - 2026-06-15

### Added

#### vwh (Public Inspector)

- **Registry commit signature check**: after fetching registry data, the inspector hits the GitHub API to verify the HEAD commit on `notvcto/vwh-registry` is GPG-signed. If it isn't, it walks back through the last 20 commits, finds the most recent signed one, and re-fetches `keys.json` and `ledger.json` at that SHA. Unsigned registry HEAD is reported as `[ERR]`. Check is skipped for `--offline` and custom `--registry` URLs.
- `vwh note <artifact.vwh>`: new subcommand to display the attached note with BLAKE3 hash verification
- `[INFO] Run 'vwh note ...'` hint in `inspect` output when a note is present and verified

### Fixed

#### vwh-core

- Seal signature test setup was computing `seal_signing_bytes()` before writing the real seal pubkey into the artifact — same root cause as the production bug fixed in 2.0.1. Fixed across all four affected tests. Added an end-to-end `crypto::verify()` assertion to `test_v2_roundtrip_sealed` that would have caught this originally.

---

## [2.0.1] - 2026-06-15

### Added

#### vwh (Public Inspector)

- `is_demo` registry field: keys flagged `"is_demo": true` trigger a `[WARN] DEMO KEY` block in inspect output, regardless of key status (active/deprecated/revoked). Separation between mathematical validity and attribution trust.

### Fixed

#### vwh-core

- **Critical**: seal signature verification failed on every V2 artifact. `seal_signing_bytes()` includes `seal_pubkey` in the signed payload, but the production `seal()` function was computing the signing bytes before writing the real pubkey into the artifact — so the signature was over 32 zero bytes, not the actual key. Verification always saw different bytes and always failed. Fixed by writing the seal pubkey (with a zero placeholder signature) before computing `seal_signing_bytes()`, then signing, then writing the real signature.

### Other

- Frame Me challenge updated to V2 dual-key structure. Reference artifact (`examples/demo-key/challenge.vwh`) regenerated with corrected seal signature.

---

## [2.0.0] - 2026-03-05

### Added

#### vwh-core

- **V2 format** (256 bytes): dual signature model with separate author and seal keys
- Author signature covers 103 bytes (artifact body through note hash)
- Seal signature covers 192 bytes (through seal pubkey, binds author signature)
- `note_hash` field: BLAKE3 hash of a detached `.vwh.note` sidecar file
- `ArtifactVersion` enum for clean v1/v2 separation
- `ArtifactBuilder::new_v2()` for V2 artifact construction
- `seal_signing_bytes()`, `seal_fingerprint()`, `has_note_hash()`, `with_seal()`, `without_seal_signature()`
- V1 artifacts (128 bytes) remain fully supported — `from_bytes()` auto-detects format by size

#### vwh (Public Inspector)

- V2 dual-signature verification: author sig and seal sig checked separately
- Separate display of author key and seal key for V2 artifacts
- Note file verification: checks sidecar presence and BLAKE3 hash match
- Versioned registry paths: `/v1/` and `/v2/` based on artifact version
- V2 state display: `SIGNED (author only, not sealed)` vs `SEALED (dual-signed, immutable)`

### Changed

- `Artifact.version` is now `ArtifactVersion` enum (was raw `u16`)
- `signature` field renamed to `author_signature`
- `author_signing_bytes()` returns 103 bytes for V2, 63 bytes for V1

### Breaking

- V2 artifacts are 256 bytes (V1: 128 bytes)
- Registry now requires versioned subdirectory layout (`/v1/`, `/v2/`)
- `Artifact.version` type changed

### Security

- Seal signature covers the author signature — prevents author sig substitution
- Note hash binds human-readable context into the cryptographic artifact
- Ceremony separation: signing key and sealing key are distinct key types

---

## [1.0.0] - 2026-02-10

### Added

#### vwh (Public Inspector)

- Ledger-backed verification via `ledger.json` (replaces `revocations.json`)
- Clear verdict messaging for sealed/draft vs ledger status
- Registry status reports ledger availability and last update time

#### vwh-core

- Ledger-friendly metadata handling

### Changed

- Registry checks now rely on ledger status for public acknowledgment

---

## [0.1.0] - 2026-02-08

### Added

#### vwh-core

- Binary format parser for `.vwh` artifacts (V1, 128 bytes)
- Ed25519 signature creation and verification
- BLAKE3 fingerprint calculation
- Intent enum: LAB, OWNED-INFRA, AUTH-REDTEAM, BLUE-REMEDIATION, RESEARCH
- 128-bit random artifact ID generation

#### vwh (Public Inspector)

- `inspect`: binary parse, Ed25519 verification, registry check (keys.json, revocations.json), offline mode
- HTTP client with 5-second timeout and graceful registry fallback

### Security

- Offline-capable verification — network is never required for signature checks
