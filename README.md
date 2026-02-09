# vwh - Victor Was Here

A public inspector for `.vwh` accountability artifacts.

## What is a .vwh file?

A `.vwh` file is a cryptographically signed artifact used to mark intentional system interaction, research, or access — acting as an accountability stamp rather than an exploit payload.

## What vwh does

- Reads `.vwh` files
- Verifies cryptographic signatures
- Displays author fingerprint and intent
- Checks public revocation registry
- Works offline (integrity-only) or online (trust-aware)

## What vwh does NOT do

- Create artifacts
- Sign artifacts
- Modify artifacts

## Registry

The public registry is hosted at:
https://notvc.to/vwh-registry

The registry is advisory and timestamped.  
Cryptographic verification is always performed locally.

## Installation

(Download binary from Releases)

## Usage

```bash
vwh inspect artifact.vwh
vwh inspect artifact.vwh --offline
```
