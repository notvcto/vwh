# VWH (Victor Was Here)

[![Crate](https://img.shields.io/crates/v/vwh.svg)](https://crates.io/crates/vwh)

VWH is a cryptographic artifact format and public inspector for proving that a specific intent was recorded at a point in time. Artifacts are immutable once signed, and verification works offline. A network registry is optional and advisory.

This repository contains only public components:

- `vwh-core` (library): format parsing, hashing, signing, verification
- `vwh` (CLI): public inspector for `.vwh` artifacts

The private authoring tool used to create and sign artifacts is intentionally not included here.

**Status:** v1 format, stable for public inspection.

**Key Ideas**

- **Offline-first**: Signature verification never depends on the network.
- **Immutable**: Signed artifacts cannot be modified without invalidating the signature.
- **Advisory registry**: Optional trust context for key status and revocations.

**Artifacts**

- Binary format, fixed size (128 bytes)
- Signed with Ed25519
- Includes a public key and intent

**Installation**

```bash
cargo build --release
```

Binaries will be at:

```bash
target/release/vwh
```

**Usage**

Binary name by OS:

- macOS/Linux: `vwh`
- Windows: `vwh.exe`

If running from build output:

- macOS/Linux: `./target/release/vwh`
- Windows (PowerShell): `.\target\release\vwh.exe`

Inspect a file:

```bash
vwh inspect artifact.vwh
```

Offline mode:

```bash
vwh inspect artifact.vwh --offline
```

Custom registry URL:

```bash
vwh inspect artifact.vwh --registry https://example.com/registry
```

Or via environment variable:

```bash
export VWH_REGISTRY_URL=https://example.com/registry
vwh inspect artifact.vwh
```

Windows (PowerShell):

```powershell
$env:VWH_REGISTRY_URL = "https://example.com/registry"
vwh.exe inspect artifact.vwh
```

Windows (CMD):

```cmd
set VWH_REGISTRY_URL=https://example.com/registry
vwh.exe inspect artifact.vwh
```

**Registry (Optional)**

If available, the inspector fetches:

- `keys.json`
- `ledger.json`

Default registry base URL:

- `https://notvc.to/vwh-registry`

Registry data is advisory only. Signature validity is always authoritative and local.

## 🏴‍☠️ The "Frame Me" Challenge

VWH relies on a separation between **Mathematical Validity** (the signatures are correct) and **Authority** (the registry says the key can be trusted for attribution).

To prove the separation actually holds, I've published **both private keys** for the official Demo Identity — the author (signing) key *and* the seal (sealing) key. With both, you can produce a fully dual-signed, immutable V2 artifact that passes every cryptographic check `vwh inspect` runs.

**I challenge you to frame me.**
Try to create a `.vwh` artifact that this tool accepts as a legitimate proof of _my_ presence (`vcto`).

### The Demo Credentials

- **Encrypted Signing Key:** [`examples/demo-key/signing.key.enc`](examples/demo-key/signing.key.enc)
- **Signing Public Key:** [`examples/demo-key/signing.pub`](examples/demo-key/signing.pub) — `c043ce6b9a8f6d4c44bb4198b92261e1a6062e6d925fe3430f1bcdbcbd07dc1c`
- **Encrypted Sealing Key:** [`examples/demo-key/sealing.key.enc`](examples/demo-key/sealing.key.enc)
- **Sealing Public Key:** [`examples/demo-key/sealing.pub`](examples/demo-key/sealing.pub) — `d7e15d78527d085a4061867f933a8be56f0daa9d8e9431f8127a0efcba0d702a`
- **Passphrase (both keys):** `vwh-demo-mode`

### Reference Artifact

A real sealed V2 artifact, signed and sealed with these exact keys, is included so you can see what "fully valid" looks like before you try to beat it:

- [`examples/challenge.vwh`](examples/demo-key/challenge.vwh)
- [`examples/challenge.vwh.note`](examples/demo-key/challenge.vwh.note)

```bash
vwh inspect examples/demo-key/challenge.vwh --offline
vwh note examples/demo-key/challenge.vwh
```

Both signatures verify. The note hash checks out. Structurally, it's indistinguishable from a real one.

### How to play

1. Decrypt both keys with the `vwh-core` library using the passphrase above.
2. Build a malicious `.vwh` draft, sign it with the **signing** key, then seal it with the **sealing** key — the same workflow used to create the reference artifact.
3. Run `vwh inspect malicious.vwh`.

### The Result

Cryptographically, your artifact will be perfect:

```
[OK] Author signature valid
[OK] Artifact integrity verified
[OK] Seal signature valid
[OK] DUAL-SIGNED (immutable)
```

But the registry knows these keys by fingerprint:

- Signing FP: `d42c5b43d040749c5147b9ead70a1497dcccd1267cb2c47e2eeaf815ae5aac40`
- Sealing FP: `5ae917a04a1f2d2d0bdb98688ed9d7c703c640278ac29fa4d6057693d4e761c3`

Both are flagged `"is_demo": true` in the registry — independent of `status` (active/deprecated/revoked). The inspector will show:

```
[WARN] DEMO KEY — do not trust for attribution
   This key is intentionally public (Frame Me challenge).
   Valid signature ≠ Victor's presence.
```

Math says the signatures are valid. The registry says don't believe it anyway. That gap *is* the point — a valid signature proves an artifact was signed with a given key, not that I was the one signing it.

**Build and Test**

```bash
cargo test --workspace
cargo fmt --check
cargo clippy --workspace -- -D warnings
```

**License**

MIT (see [`LICENSE`](LICENSE)).
