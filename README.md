# VWH — Victor Was Here

[![Crate](https://img.shields.io/crates/v/vwh.svg)](https://crates.io/crates/vwh)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A cryptographic artifact format for proving that a specific intent was recorded at a specific point in time, by a specific key, not just a specific person. That distinction is the whole point.

**Signatures prove key possession. The registry provides attribution context.** Those are two separate claims, and VWH keeps them separate by design.

---

## What it is

You create an artifact with an intent (a string. A commitment, a decision, a statement). You sign it with your Ed25519 signing key. Optionally, you seal it with a separate sealing key, making it immutable. The artifact is 256 bytes. It verifies offline. The registry is advisory.

```
Draft → Signed → Sealed
```

- **Draft**: intent recorded, key bound, no signature yet
- **Signed**: author signature covers the artifact + note hash
- **Sealed**: second signature from a separate sealing key; the artifact is now immutable

V2 artifacts carry a BLAKE3 note hash. The note itself lives in a `.vwh.note` sidecar file. If the hash doesn't match, `vwh inspect` tells you.

---

## Install

```bash
cargo install vwh
```

Or build from source:

```bash
cargo build --release
# binary at target/release/vwh
```

---

## Usage

**Inspect an artifact:**

```bash
vwh inspect artifact.vwh
```

**Read the attached note:**

```bash
vwh note artifact.vwh
```

**Offline (skip registry check):**

```bash
vwh inspect artifact.vwh --offline
```

**Custom registry:**

```bash
vwh inspect artifact.vwh --registry https://example.com/vwh-registry
# or
export VWH_REGISTRY_URL=https://example.com/vwh-registry
vwh inspect artifact.vwh
```

---

## What `vwh inspect` checks

In order:

1. **Artifact parse** — is this a valid `.vwh` file?
2. **Note verification** — if V2, does the sidecar hash match?
3. **Author signature** — Ed25519 over the artifact body
4. **Seal signature** — if sealed, Ed25519 over the artifact including the seal key
5. **Registry commit signature** — is the latest commit to the registry GPG-signed? If not, falls back to the last signed commit
6. **Key status** — is the signing key active, deprecated, or revoked? If deprecated, did the artifact predate the rotation?
7. **Ledger status** — is this artifact publicly acknowledged, or sealed but absent from the ledger (suspicious)?

A valid signature with an unsigned registry commit gets called out. A valid signature from a demo key gets called out. The output doesn't hide things.

---

## Registry

Default registry: `https://notvc.to/vwh-registry`

The registry is backed by a public git repo (`github.com/notvcto/vwh-registry`). Before trusting registry data, the inspector checks whether the HEAD commit is GPG-signed. If it isn't (possible tampered push, CI key, or mistake) it walks back through the last 20 commits, finds the most recent signed one, and fetches `keys.json` and `ledger.json` at that SHA instead.

Registry data is always advisory. Signature verification is always local and offline-first.

---

## 🏴‍☠️ The "Frame Me" Challenge

VWH separates two things that look identical from the outside: **a valid signature** and **a trustworthy attribution**.

To prove the gap is real, I've published both private keys for the official demo identity; the signing key and the sealing key. With them, you can produce a perfectly dual-signed V2 artifact that passes every cryptographic check `vwh inspect` runs.

**I challenge you to frame me.**

### The demo credentials

| | |
|---|---|
| Signing key (encrypted) | [`examples/demo-key/signing.key.enc`](examples/demo-key/signing.key.enc) |
| Signing public key | `c043ce6b9a8f6d4c44bb4198b92261e1a6062e6d925fe3430f1bcdbcbd07dc1c` |
| Sealing key (encrypted) | [`examples/demo-key/sealing.key.enc`](examples/demo-key/sealing.key.enc) |
| Sealing public key | `d7e15d78527d085a4061867f933a8be56f0daa9d8e9431f8127a0efcba0d702a` |
| Passphrase (both keys) | `vwh-demo-mode` |

A real sealed V2 artifact signed with these exact keys is included so you can see what "fully valid" looks like before you try to beat it:

```bash
vwh inspect examples/demo-key/challenge.vwh
vwh note examples/demo-key/challenge.vwh
```

### How to play

1. Decrypt the keys using the `vwh-core` library and the passphrase above
2. Build a `.vwh` draft, sign it with the signing key, seal it with the sealing key
3. Run `vwh inspect your-artifact.vwh`

### What you get

```
[OK] Author signature valid
[OK] Artifact integrity verified
[OK] Seal signature valid
[OK] DUAL-SIGNED (immutable)
```

And then:

```
[WARN] DEMO KEY — do not trust for attribution
   This key is intentionally public (Frame Me challenge).
   Valid signature ≠ Victor's presence.
```

The registry flags these keys `"is_demo": true`. Independently of status. A valid signature from a key I've published to the world proves nothing about who was holding it.

**That gap is the point.** Cryptography proves key possession. Attribution requires a trust model on top of it. VWH makes you look at both separately, not conflate them.

---

## Architecture

```
vwh-core    — format, parsing, signing, verification (library)
vwh         — public inspector CLI (this crate)
```

The private authoring tool (`vwh-author`) is not published. It handles key generation, signing, sealing, key rotation, revocation, and registry publishing.

---

## Build & test

```bash
cargo test --workspace
cargo fmt --check
cargo clippy --workspace -- -D warnings
```

---

## License

MIT — see [`LICENSE`](LICENSE).
