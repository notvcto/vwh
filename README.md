# VWH (Victor Was Here)

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

**Registry (Optional)**

If available, the inspector fetches:

- `keys.json`
- `ledger.json`

Default registry base URL:

- `https://notvc.to/vwh-registry`

Registry data is advisory only. Signature validity is always authoritative and local.

## 🏴‍☠️ The "Frame Me" Challenge

VWH relies on a separation between **Mathematical Validity** (the signature is correct) and **Authority** (the key is trusted).

To prove this, I have published the **Private Key** for the official Demo Identity.

**I challenge you to frame me.**
Try to create a VWH artifact that this tool accepts as a legitimate proof of _my_ presence (`vcto`).

### The Demo Credentials

- **Encrypted Private Key:** [`examples/demo-key/identity.key.enc`](examples/demo-key/identity.key.enc)
- **Public Key:** [`examples/demo-key/identity.pub`](examples/demo-key/identity.pub)
- **Passphrase:** `vwh-demo-mode`

### How to play:

1. Use the `vwh-core` library to decrypt the key and sign a malicious artifact.
2. Run `vwh inspect malicious.vwh`.

**The Result:**
You will see that while the signature is **✅ Valid**, the identity will be flagged as **⚠️ UNTRUSTED / DEMO**.

This proves that even if a key is compromised (or public!), the Registry prevents unauthorized attribution.

**Build and Test**

```bash
cargo test --workspace
cargo fmt --check
cargo clippy --workspace -- -D warnings
```

**License**

MIT (see [`LICENSE`](LICENSE)).
