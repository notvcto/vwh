# vwh-core

Core library for the VWH artifact format. This crate provides:

- Binary format parsing/serialization for v1 artifacts
- Ed25519 signing and verification helpers
- Artifact state utilities (draft/signed/sealed)
- Key fingerprinting (BLAKE3)

The public CLI (`vwh`) depends on this crate. The private authoring tool is intentionally not part of this repo.

Windows prerequisite (when building from source or installing tools that depend on this crate):

- The MSVC linker (`link.exe`) is required. Install "Build Tools for Visual Studio" with the "Desktop development with C++" workload, then reopen your terminal.

## Format Summary (v1)

- Fixed size: 128 bytes
- Magic: `VWH\0`
- Fields: version, flags, artifact id, timestamp, intent, author public key, signature
- Signature: Ed25519 over the **signing bytes** (see below)

Important: the `flags` byte is **not** included in the signing bytes. This allows sealing to be a state transition without invalidating the signature.

## API Highlights

- `Artifact::from_bytes` / `Artifact::to_bytes`
- `ArtifactBuilder` for constructing unsigned artifacts
- `UnsignedArtifact::signing_bytes` + `UnsignedArtifact::with_signature`
- `verify::verify_artifact` for signature verification
- `crypto::sign` / `crypto::verify` helpers

## Example

```rust
use vwh_core::{
    crypto, verify,
    format::{ArtifactBuilder},
    Intent,
};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

let signing_key = SigningKey::generate(&mut OsRng);
let public_key = signing_key.verifying_key().to_bytes();

// Build an unsigned artifact
let unsigned = ArtifactBuilder::new(Intent::Lab, public_key).build_unsigned();
let signing_bytes = unsigned.signing_bytes();

// Sign and finalize
let signature = crypto::sign(&signing_key, &signing_bytes);
let artifact = unsigned.with_signature(signature);

// Verify
verify::verify_artifact(&artifact)?;
```

## Notes

- Artifacts are immutable once sealed.
- Signatures are always verified locally.
- This crate is format- and crypto-focused; registry logic lives elsewhere.
