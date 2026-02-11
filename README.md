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

VWH separates **Mathematical Validity** from **Authority**.

To demonstrate this, I've published the demo key with its passphrase.

**Your mission:** Use `vwh-core` to create a malicious artifact.

**What you have:**

- Demo private key: [`examples/demo-key/identity.key.enc`](examples/demo-key/identity.key.enc)
- Demo public key: [`examples/demo-key/identity.pub`](examples/demo-key/identity.pub)
- Passphrase: `vwh-demo-mode`
- Full vwh-core library source code

**The result:**
Your artifact will have a ✅ **cryptographically valid signature**  
But registry will flag it as ⚠️ **UNTRUSTED/DEMO**

**This proves:** Even with a compromised key, the registry prevents
unauthorized attribution.

**Hint:** Everything you need is in `vwh-core`. Start with
`ArtifactBuilder` and `signing_bytes()`.

```bash
cargo test --workspace
cargo fmt --check
cargo clippy --workspace -- -D warnings
```

**License**

MIT (see [`LICENSE`](LICENSE)).
