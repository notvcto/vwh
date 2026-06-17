# vwh-core

Core library for the VWH artifact format. This crate provides:

- Binary format parsing/serialization for V1 (128 bytes) and V2 (256 bytes) artifacts
- Ed25519 signing and verification with domain separation
- Dual-signature model: separate author and seal keys (V2)
- Artifact lifecycle state machine: Draft → Signed → Sealed
- Key fingerprinting (BLAKE3)

The public CLI (`vwh`) depends on this crate. The private authoring tool is intentionally not part of this repo.

Windows prerequisite (when building from source or installing tools that depend on this crate):

- The MSVC linker (`link.exe`) is required. Install "Build Tools for Visual Studio" with the "Desktop development with C++" workload, then reopen your terminal.

## Format Summary

### V2 (current, default — 256 bytes)

- Magic: `VWH\0`
- Fields: version, reserved, artifact id, timestamp, intent, author public key, note hash, author signature, seal public key, seal signature
- Author signature: Ed25519 over the first 103 bytes (through note hash)
- Seal signature: Ed25519 over the first 192 bytes (through seal public key — binds the author signature)
- Note hash: BLAKE3 of a detached `.vwh.note` sidecar file
- All Ed25519 operations prepend `b"vwh-v2\x00"` (domain separation)

### V1 (legacy — 128 bytes)

- Magic: `VWH\0`
- Fields: version, flags, artifact id, timestamp, intent, author public key, signature
- The `flags` byte is excluded from signing bytes — sealing is a state transition that does not invalidate the signature
- V1 artifacts are fully supported; `Artifact::from_bytes` auto-detects format by version field

## API Highlights

- `Artifact::from_bytes` / `Artifact::to_bytes` — parse and serialize (auto-detects V1/V2)
- `ArtifactBuilder::new_v2` / `ArtifactBuilder::new_v1` — construct unsigned artifacts
- `UnsignedArtifact::author_signing_bytes` + `UnsignedArtifact::with_author_signature`
- `Artifact::seal_signing_bytes` — bytes covered by the seal signature (V2 only)
- `verify::verify_artifact` — author signature verification
- `verify::verify_seal` — seal signature verification (V2 only)
- `crypto::sign` / `crypto::verify` — raw Ed25519 helpers (domain separation applied internally)
- `TypedArtifact<S>` — zero-cost phantom wrapper encoding state (`Draft`, `Signed`, `Sealed`) in the type system
- `KeyFingerprint` — BLAKE3 fingerprint of an Ed25519 public key

## Example

```rust
use vwh_core::{
    crypto, verify,
    format::{ArtifactBuilder},
    Intent,
};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

let author_key = SigningKey::generate(&mut OsRng);
let seal_key = SigningKey::generate(&mut OsRng);
let author_pubkey = author_key.verifying_key().to_bytes();
let seal_pubkey = seal_key.verifying_key().to_bytes();

let note = b"human-readable context for this artifact";
let note_hash = *blake3::hash(note).as_bytes();

// Build and author-sign a V2 artifact
let unsigned = ArtifactBuilder::new_v2(Intent::Lab, author_pubkey, note_hash).build_unsigned();
let author_sig = crypto::sign(&author_key, &unsigned.author_signing_bytes());
let signed = unsigned.with_author_signature(author_sig);

// Seal it (dual-sign)
let pre_seal = signed.with_seal(seal_pubkey, [0u8; 64]);
let seal_sig = crypto::sign(&seal_key, &pre_seal.seal_signing_bytes()?);
let sealed = pre_seal.with_seal(seal_pubkey, seal_sig);

// Verify both signatures
verify::verify_artifact(&sealed)?;
verify::verify_seal(&sealed)?;
```

## Notes

- Artifacts are immutable once sealed.
- Signatures are always verified locally — network is never required for cryptographic checks.
- This crate is format- and crypto-focused; registry logic lives in the `vwh` CLI.
