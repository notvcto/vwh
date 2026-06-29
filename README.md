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

As of **4.0**, `vwh` is a **single binary** that does both halves of the system: **inspecting** (no keys required) and **authoring** (create / sign / seal / rotate / revoke / publish). There is no separate `vwh-author` tool anymore.

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

## Two roles

`vwh` serves two audiences from one binary:

- **Inspectors** verify artifacts. They never need keys or a keystore.
- **Authors** hold keys and produce artifacts. Their identity lives in `~/.vwh` (see [Keystore](#keystore)).

### Inspecting

```bash
vwh inspect artifact.vwh           # verify signatures + registry status
vwh note artifact.vwh              # show the attached note (BLAKE3-verified)
vwh inspect artifact.vwh --offline # skip the registry, crypto only
```

Override the registry an artifact points at:

```bash
vwh inspect artifact.vwh --registry https://example.com/vwh-registry
# or
export VWH_REGISTRY_URL=https://example.com/vwh-registry
vwh inspect artifact.vwh
```

### Authoring

```bash
# One-time: create a signing identity and a sealing identity
vwh key init --type signing
vwh key init --type sealing

# Author → sign → seal
vwh create --intent lab            # writes artifact.vwh + artifact.vwh.note
vwh sign  artifact.vwh
vwh seal  artifact.vwh

# Inspect what you just made
vwh inspect artifact.vwh --offline
```

Other authoring commands:

| Command | What it does |
|---|---|
| `vwh key show [name]` | Display a key's public key + fingerprint |
| `vwh key rotate` | Generate a new key, mark the old one deprecated |
| `vwh unseal <file>` | Remove a seal (V2), returning to Signed |
| `vwh unsign <file>` | Strip the author signature back to a keyless draft |
| `vwh edit <file>` | Edit draft metadata (intent) |
| `vwh revoke key --reason ...` | Revoke a signing/sealing key |
| `vwh revoke artifact <id> --reason ...` | Revoke an artifact in the ledger |
| `vwh dump keys` / `vwh dump ledger` | Print local registry state as JSON |
| `vwh push` | Publish the local registry to the remote git repo (GPG-signed commit) |

### Coming in 4.x

The following lifecycle commands are scaffolded in the CLI and will be filled in across the 4.x series. They currently print a "not yet implemented" notice:

`vwh init` (guided first-time setup) · `vwh config` (manage configuration) · `vwh rebase` (rebase the local registry) · `vwh export` (encrypted backup of `~/.vwh`) · `vwh restore` (restore from a backup).

---

## Keystore

Authoring state lives under `~/.vwh`:

```
~/.vwh/
├── keys/<name>/        identity.key.enc, identity.pub, metadata.json
├── keys.json           local key registry
├── ledger.json         local artifact ledger
└── registry/           git clone of the published registry
```

Private keys are encrypted with Argon2id + ChaCha20-Poly1305 and never written in the clear.

**Upgrading from 3.x?** Earlier releases stored author state under the platform config dir for `vwh-author` (e.g. `~/.config/vwh-author`). The first time you run any `vwh` command, that state is **copied** into `~/.vwh` automatically — keys are nested under `keys/`, and your originals are left untouched until you've verified the move.

---

## Per-artifact registry

Trust is not centralized on `notvc.to`. Each artifact created by 4.0 records the registry it belongs to in its `.vwh.note` header:

```
registry: https://notvc.to/vwh-registry

<your human-readable note body>
```

The whole note — header included — is what gets BLAKE3-hashed into the artifact, so the declared registry is as tamper-evident as the note itself. When inspecting, `vwh` consults that registry by default. Precedence is: `--registry` / `VWH_REGISTRY_URL` > the artifact's declared registry > the built-in default. Set your own with `VWH_REGISTRY_URL` at `create` time, and anyone can run their own registry.

---

## What `vwh inspect` checks

In order:

1. **Artifact parse** — is this a valid `.vwh` file?
2. **Note verification** — if V2, does the sidecar hash match? (the registry is read from the verified note)
3. **Author signature** — Ed25519 over the artifact body
4. **Seal signature** — if sealed, Ed25519 over the artifact including the seal key
5. **Registry anchoring** — the registry's `index.html` declares its backing GitHub repo; the inspector GPG-checks that repo's commit and reads `keys.json`/`ledger.json` **at the verified SHA** (falling back to the last signed commit if HEAD isn't signed). No repo declared → registry data is advisory (TLS only).
6. **Key status** — is the signing key active, deprecated, or revoked? If deprecated, did the artifact predate the rotation?
7. **Ledger status** — is this artifact publicly acknowledged, or sealed but absent from the ledger (suspicious)?

A valid signature with an unsigned registry commit gets called out. A valid signature from a demo key gets called out. The output doesn't hide things.

---

## Registry

Default registry: `https://notvc.to/vwh-registry`

A registry is any GitHub-Pages site that serves `keys.json`/`ledger.json` plus an `index.html` declaring its backing repo:

```html
<meta name="vwh-registry-repo" content="owner/repo">
```

The inspector reads that descriptor over TLS, asks the GitHub API whether the repo's commit is GPG-signed, and pulls the registry data **at the verified commit's SHA** — so the published Pages copy lagging behind the repo never matters. `notvc.to` is just the *default value*, verified through the exact same path as anyone else's registry; there is no hardcoded special case. The repo is asserted by the registry operator (via its own `index.html`), not by the artifact, so an artifact can't redirect verification to an arbitrary repo.

Registry data is always advisory — a signed, repo-backed registry proves *"this data was committed by GitHub account X,"* not that X is who you should trust. Signature verification is always local and offline-first.

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
vwh inspect examples/challenge.vwh
vwh note examples/challenge.vwh
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
vwh-core    — format, parsing, signing, verification (library, on crates.io)
vwh         — the single CLI: inspect + author (this crate)
```

`vwh-core` is the reusable, crypto-and-format-only library. `vwh` is the one binary everyone installs; whether you're verifying someone else's artifact or minting your own, it's the same tool. (Prior to 4.0, authoring lived in a separate, unpublished `vwh-author` binary — that split is gone.)

---

## Build & test

```bash
cargo test --workspace
cargo fmt --check
cargo clippy --workspace -- -D warnings
# or run all of the above:
./build.sh
```

---

## License

MIT — see [`LICENSE`](LICENSE).
