# VWH (Victor Was Here) System Specification

**Version:** 1
**Status:** Public, stable

---

## Overview

VWH defines a fixed-size binary artifact format and a public verification flow. Artifacts are signed with Ed25519 and are verifiable offline. A network registry is optional and advisory, used only for key status and public artifact acknowledgment.

---

## Artifact Format (v1)

Binary layout (128 bytes total):

```
[ MAGIC        ]  4 bytes   "VWH\0"
[ VERSION      ]  2 bytes   u16 little-endian
[ FLAGS        ]  1 byte    bitfield (see below)
[ ARTIFACT_ID  ] 16 bytes   random 128-bit identifier
[ TIMESTAMP    ]  8 bytes   u64 little-endian Unix seconds
[ INTENT       ]  1 byte    enum (0-4)
[ AUTHOR_PUBKEY] 32 bytes   Ed25519 public key
[ SIGNATURE    ] 64 bytes   Ed25519 signature
```

### Flags

- Bit 0: `SEALED` (1 = sealed, 0 = unsealed)

### Signature Coverage

The signature covers all fields **except** `FLAGS` and the `SIGNATURE` itself. This allows the sealed flag to be toggled without re-signing while preserving artifact identity.

Signed bytes (in order):
- `MAGIC`
- `VERSION`
- `ARTIFACT_ID`
- `TIMESTAMP`
- `INTENT`
- `AUTHOR_PUBKEY`

---

## Intent Enum

```
0 = LAB
1 = OWNED-INFRA
2 = AUTH-REDTEAM
3 = BLUE-REMEDIATION
4 = RESEARCH
```

No default value. Intent must be explicit in the artifact.

---

## Cryptography

- **Signature algorithm:** Ed25519
- **Signature size:** 64 bytes
- **Public key size:** 32 bytes
- **Fingerprint:** BLAKE3(public_key)

---

## Verification Flow

1. Read file (must be exactly 128 bytes)
2. Parse and validate fields
3. Verify Ed25519 signature over the signed bytes
4. Optionally fetch registry status

Signature verification is authoritative and local. Registry data is advisory only.

---

## Registry (Optional)

Default registry base URL:
- `https://notvc.to/vwh-registry`

The inspector fetches:
- `keys.json`
- `ledger.json`

### keys.json

```json
{
  "version": 1,
  "updated_at": "ISO8601",
  "keys": [
    {
      "fingerprint": "64-char hex (BLAKE3)",
      "public_key": "64-char hex (Ed25519)",
      "created_at": "ISO8601",
      "status": "active|deprecated|revoked",
      "label": "optional string"
    }
  ]
}
```

### ledger.json

```json
{
  "version": 1,
  "updated_at": "ISO8601",
  "artifacts": [
    {
      "id": "32-char hex",
      "fingerprint": "64-char hex",
      "status": "active|revoked",
      "revoked_at": "ISO8601",
      "reason": "string"
    }
  ]
}
```

**Semantics:**
- `active`: artifact is publicly acknowledged in the ledger
- `revoked`: artifact is explicitly revoked by the author
- `revoked_at` and `reason` are required for `revoked` entries

---

## Trust Model

- **Authoritative:** local cryptographic verification
- **Advisory:** registry key status and public artifact acknowledgment
- **Offline-first:** registry failures never invalidate a signature

---

## Notes

- Artifacts are immutable once signed.
- Sealing is a state transition that does not change the signed bytes.
- Future versions may extend the format while preserving v1 parsing rules.
