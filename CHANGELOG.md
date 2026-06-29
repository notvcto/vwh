# Changelog

All notable changes to VWH are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) — Versioning: [SemVer](https://semver.org/spec/v2.0.0.html)

---

## [4.0.1] - 2026-06-29

### Changed

- **Dropped the `rand` dependency in favor of `getrandom`.** All randomness in the
  project — artifact IDs (`ArtifactId::new`), Ed25519 key generation, and the
  Argon2id salts / ChaCha20-Poly1305 nonces in the keystore — is now sourced
  directly from the OS via `getrandom::fill`. `SigningKey::generate` is replaced by
  seeding 32 bytes and calling `SigningKey::from_bytes`, an identical result with no
  RNG trait plumbing. This removes a dependency and dissolves the
  `ed25519-dalek` ↔ `rand_core` version conflict that blocked bumping `rand`.
- No public API change and **no on-disk format change** — v2 (256-byte) artifacts
  created by any 4.0.x release verify identically. Bytes out of the RNG are the same
  shape; only their source crate changed.

---

## [4.0.0] - 2026-06-29

### Breaking

- **One binary.** The previously-private `vwh-author` tool is merged into the
  public `vwh` binary. Authoring (`create`, `sign`, `seal`, `unseal`, `unsign`,
  `edit`, `key`, `revoke`, `dump`, `push`) and inspecting (`inspect`, `note`)
  now ship together. `vwh-author` no longer exists as a separate binary or repo.
- **Keystore moved to `~/.vwh`.** Author state (keys, `keys.json`, `ledger.json`,
  registry clone) now lives under `~/.vwh`, with keys nested under `~/.vwh/keys/`.
  Previous releases used the platform config dir for `vwh-author`
  (e.g. `~/.config/vwh-author`).

### Added

#### vwh

- **Automatic keystore migration**: on first run, an existing
  `~/.config/vwh-author` keystore is **copied** into `~/.vwh` (keys nested under
  `keys/`). Non-destructive and idempotent — originals are left in place until
  you remove them.
- **Per-artifact registry**: `create` stamps a `registry:` header into the
  `.vwh.note` (covered by `NOTE_HASH`, so it is tamper-evident). `inspect`
  resolves the registry as `--registry`/`VWH_REGISTRY_URL` > the note's declared
  registry > the built-in default. Source the value at creation time with
  `VWH_REGISTRY_URL`.
- **Registry discovery + commit anchoring (generic)**: a registry serves an
  `index.html` declaring its backing GitHub repo
  (`<meta name="vwh-registry-repo" content="owner/repo">`). `inspect` reads that
  descriptor, GPG-verifies the repo's commit, and reads `keys.json`/`ledger.json`
  **at the verified SHA** (no longer the lagging Pages copy). Registries with no
  declared repo are treated as advisory (TLS only). The hardcoded
  `notvcto/vwh-registry` constant is removed — notvc.to is now just the default
  registry, verified through the same path as any community registry.
- **Lifecycle commands scaffolded**: `init`, `config`, `rebase`, `export`,
  `restore` exist in the CLI and currently report "not yet implemented"; they
  will be filled in across the 4.x series.

### Changed

- `vwh-core` bumped to 4.0.0 (no API or format change from 3.0.0; version
  realigned with the unified release line).
- The artifact binary format is **unchanged** — v2 (256 bytes) artifacts created
  by 3.x verify identically under 4.0.

### Other

- Single public repository; the private `vwh-author` repo is retired.
- Documentation (README, crate READMEs, SPEC, man page) updated for the unified
  tool.

---

## [3.0.0] - 2026-06-17

### Breaking

#### vwh-core

- **Domain-separated signing** (ARCH-5): `crypto::sign` and `crypto::verify` now prepend
  `b"vwh-v2\x00"` (7 bytes) to the message before Ed25519 operations. The on-disk artifact
  format is unchanged, but signatures produced by releases ≤2.0.2 will fail verification
  under 3.0.0 and vice versa.
- `seal_signing_bytes()` now returns `Result<Vec<u8>>`; returns `Err(NoSeal)` for artifacts
  with no seal instead of silently producing bytes over a zero pubkey.

### Added

#### vwh-core

- `verify_seal(artifact)` — dedicated function for seal signature verification
- `TypedArtifact<S>` phantom-type wrapper with `Draft`, `Signed`, `Sealed` marker types —
  encodes artifact lifecycle state in the type system; zero runtime cost
- `Error::KeyMalformed`, `Error::NoSeal`, `Error::InvalidState` variants

#### vwh (Public Inspector)

- **Sealing key registry check**: seal key fingerprint now looked up in `keys.json`; status
  (active / deprecated / revoked), label, `is_demo` flag, and time-gating all apply — same
  as signing key
- `LedgerEntry.created_at`: artifact creation timestamp stored in ledger on seal
- Exit code contract: 0 = verified, 1 = fatal error, 2 = crypto failure,
  3 = registry unavailable (crypto still passed)

### Fixed

#### vwh-core

- `is_sealed()` delegates to `state()` — eliminates the prior disagreement between the
  direct field-check path and the state machine
- `KeyFingerprint::Display` now outputs full 64-char hex; use `short_display()` for the
  short form explicitly
- Removed dead `RevocationReason` enum (zero usages)

#### vwh (Public Inspector)

- All diagnostic output uses `stderr`; `stdout` reserved for verified artifact data
- Single `reqwest::blocking::Client` with `redirect::Policy::none()` reused across all
  registry fetches (was rebuilt per call)
- `exit(3)` when registry is unavailable but crypto verification passed (was falling through)
- Revoked key check now fires and exits before status display block

### Other

- Demo artifact (`examples/challenge.vwh`) re-signed and re-sealed under v3.0.0
  domain-separated signatures

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
