# vwh

Public inspector CLI for VWH artifacts (`.vwh`). This tool verifies signatures locally and can optionally consult a public registry for key and artifact status.

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

## Usage

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

Environment variable:

```bash
export VWH_REGISTRY_URL=https://example.com/registry
vwh inspect artifact.vwh
```

Windows (PowerShell):

```powershell
$env:VWH_REGISTRY_URL = "https://example.com/registry"
vwh.exe inspect artifact.vwh
```

## Registry

If available, the inspector fetches:

- `keys.json`
- `ledger.json`

Default registry base URL:

- `https://notvc.to/vwh-registry`

Registry data is advisory only. Signature validity is always authoritative and local.
