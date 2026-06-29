# vwh

The VWH command-line tool — one binary for both **inspecting** `.vwh` artifacts and **authoring** them. Signatures are verified locally; a public registry is optionally consulted for key and artifact status.

As of 4.0 this single `vwh` binary replaces the old split between a public inspector and a private `vwh-author` tool.

## Install

From crates.io:

```bash
cargo install vwh
```

Windows prerequisite:

- The MSVC linker (`link.exe`) is required. Install "Build Tools for Visual Studio" with the "Desktop development with C++" workload, then reopen your terminal.

Build from source:

```bash
cargo build --release -p vwh
```

Binary location:

- macOS/Linux: `target/release/vwh`
- Windows: `target/release/vwh.exe`

## Inspecting (no keys required)

```bash
vwh inspect artifact.vwh             # verify signatures + registry status
vwh note artifact.vwh                # show the BLAKE3-verified note
vwh inspect artifact.vwh --offline   # local crypto only
vwh inspect artifact.vwh --registry https://example.com/registry
```

The registry can also be set via the `VWH_REGISTRY_URL` environment variable. Precedence: `--registry` / env > the registry the artifact declares in its note > the built-in default (`https://notvc.to/vwh-registry`).

## Authoring (keys live in `~/.vwh`)

```bash
vwh key init --type signing          # create a signing identity
vwh key init --type sealing          # create a sealing identity
vwh create --intent lab              # author a draft (+ .vwh.note)
vwh sign  artifact.vwh               # author-sign
vwh seal  artifact.vwh               # dual-sign → immutable
```

Also: `key show`, `key rotate`, `unseal`, `unsign`, `edit`, `revoke key`, `revoke artifact`, `dump keys|ledger`, and `push` (publish the registry). Private keys are encrypted at rest with Argon2id + ChaCha20-Poly1305.

`init`, `config`, `rebase`, `export`, and `restore` are scaffolded and arrive across the 4.x series.

Upgrading from 3.x: existing `~/.config/vwh-author` state is copied into `~/.vwh` automatically on first run; originals are left untouched.

## Registry

If available, the inspector fetches `keys.json` and `ledger.json` from the registry the artifact points at (default `https://notvc.to/vwh-registry`). Registry data is advisory only — signature validity is always authoritative and local.
