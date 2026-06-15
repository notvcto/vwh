# VWH (Victor Was Here) System Specification

**Version:** 2
**Status:** Public, stable. V2 is the actively maintained and verified format.
V1 is preserved for historical/registration purposes only (see Appendix A) and is
**not** actively verified by current tooling.

---

## Overview

VWH defines a fixed-size binary artifact format and a public verification flow.
Artifacts are signed with Ed25519 and are verifiable offline. A network registry
is optional and advisory, used only for key status and public artifact
acknowledgment.

V2 introduces:
- A larger 256-byte layout
- A detached human-readable **note**, content-bound via a BLAKE3 hash
- A **dual-signature** model separating *authorship* from *sealing* (finalization)
- **Key type separation**: signing keys (author authority) vs. sealing keys
  (finalization authority)

---

## Artifact Format (v2)

Binary layout (256 bytes total):

| Offset | Size | Field              | Notes |
|--------|------|--------------------|-------|
| 0      | 4    | `MAGIC`            | `"VWH\0"` |
| 4      | 2    | `VERSION`          | u16 little-endian (`= 2`) |
| 6      | 1    | `RESERVED_A`       | reserved, always `0x00` (see "Reserved Byte" below) |
| 7      | 16   | `ARTIFACT_ID`      | random 128-bit identifier |
| 23     | 8    | `TIMESTAMP`        | u64 little-endian Unix seconds |
| 31     | 1    | `INTENT`           | enum (0-4) |
| 32     | 32   | `AUTHOR_PUBKEY`    | Ed25519 public key (signing key) |
| 64     | 32   | `NOTE_HASH`        | BLAKE3 hash of the detached note file |
| 96     | 64   | `AUTHOR_SIGNATURE` | Ed25519 signature |
| 160    | 32   | `SEAL_PUBKEY`      | Ed25519 public key (sealing key), all-zero until sealed |
| 192    | 64   | `SEAL_SIGNATURE`   | Ed25519 signature, all-zero until sealed |

Total: 256 bytes.

The first 96 bytes (`MAGIC` through `NOTE_HASH`) plus `AUTHOR_SIGNATURE` correspond
to the v1 fields they extend (`MAGIC` through `SIGNATURE`, renamed
`AUTHOR_SIGNATURE`), with `NOTE_HASH` newly inserted before the signature.
`SEAL_PUBKEY` and `SEAL_SIGNATURE` are appended after, bringing the total to
256 bytes.

> **Verified against implementation:** the table above reflects
> `crates/vwh-core/src/format.rs` (`from_bytes_v2` / `to_bytes_v2`) as of this
> writing. If the struct's field order changes, update this table to match —
> the Rust struct is ground truth.

### Reserved Byte (v2) / Flags (v1)

In v1, byte offset 6 is `FLAGS`, a bitfield where bit 0 (`SEALED`) indicates
sealed state. In v2, the field at the same wire offset is `RESERVED_A`, an
unrelated reserved byte that tooling must write as `0x00`. These are distinct
fields in the implementation (`flags: u8` for v1, `reserved_a: u8` for v2) —
v2 does not use a flag bit for sealed state at all; sealed state is derived
from `SEAL_SIGNATURE` (see "Artifact States" below).

---

## Fields of Note (New in V2)

### NOTE_HASH

Every v2 artifact has a companion **note file**, distributed alongside the
binary artifact with the conventional name `<artifact>.vwh.note`. The note is
a plain UTF-8 text file containing a human-readable description of the
artifact's purpose, authored interactively at creation time.

`NOTE_HASH` is `BLAKE3(note_file_bytes)`. A verifier with access to both files
can confirm the note has not been altered or substituted independently of the
artifact.

The note is **required** for v2 artifacts — an empty or missing note is a
validation error at creation time.

### SEAL_PUBKEY / SEAL_SIGNATURE

These fields are all-zero (`ZERO_PUBKEY` / `ZERO_SIGNATURE`) for artifacts that
have not yet been sealed. Sealing populates both fields with a second,
independent Ed25519 keypair's public key and signature — see "Dual Signature
Model" below.

---

## Intent Enum

```
0 = LAB
1 = OWNED-INFRA
2 = AUTH-REDTEAM
3 = BLUE-REMEDIATION
4 = RESEARCH
```

No default value. Intent must be explicit in the artifact. Unchanged from v1.

---

## Cryptography

- **Signature algorithm:** Ed25519
- **Signature size:** 64 bytes
- **Public key size:** 32 bytes
- **Key fingerprint:** `BLAKE3(public_key)`
- **Note hash:** `BLAKE3(note_file_bytes)`

### Key Types

V2 separates cryptographic authority into two distinct key types. A given
keypair is *one or the other*, never both, and tooling enforces this:

| Key type   | Used for                          | Produces        |
|------------|------------------------------------|------------------|
| `signing`  | Authoring an artifact (`sign`)     | `AUTHOR_SIGNATURE` over `AUTHOR_PUBKEY` |
| `sealing`  | Finalizing an artifact (`seal`)    | `SEAL_SIGNATURE` over `SEAL_PUBKEY` |

This separation means a compromised sealing key cannot be used to forge
authorship of new artifacts, and a compromised signing key cannot be used to
seal (finalize) artifacts it didn't author.

---

## Dual Signature Model

### Author Signature

Computed at `sign` time, over a 96-byte signing payload: bytes 0-95 of the
layout above (`MAGIC` through `NOTE_HASH`, inclusive — i.e. everything before
`AUTHOR_SIGNATURE`). Signed with the **signing key**; the resulting signature
is written to `AUTHOR_SIGNATURE` and the corresponding public key to
`AUTHOR_PUBKEY`.

This binds the artifact's identity, intent, timestamp, and note content to a
specific signing key, before any sealing decision is made.

### Seal Signature

Computed at `seal` time, over a 192-byte signing payload: bytes 0-191 of the
layout above (`MAGIC` through `SEAL_PUBKEY`, inclusive — i.e. everything
before `SEAL_SIGNATURE`, which includes `AUTHOR_SIGNATURE` and `SEAL_PUBKEY`
itself). Signed with the **sealing key**; the resulting signature is written
to `SEAL_SIGNATURE`.

By including `AUTHOR_SIGNATURE` in the seal payload, sealing cryptographically
attests to *that specific signed artifact* — any change to the author
signature (e.g. re-signing) invalidates the seal.

### Unsealing

`unseal` removes `SEAL_SIGNATURE` and `SEAL_PUBKEY` (resetting them to zero),
returning the artifact to the Signed state without affecting
`AUTHOR_SIGNATURE`. This allows re-sealing with a different sealing key. V1
artifacts cannot be unsealed (see Appendix A) — use `unsign` instead.

---

## Artifact States

State is derived, not stored:

| State    | Condition                                              |
|----------|----------------------------------------------------------|
| `Draft`  | `AUTHOR_SIGNATURE` is all-zero                            |
| `Signed` | `AUTHOR_SIGNATURE` is non-zero, `SEAL_SIGNATURE` is all-zero |
| `Sealed` | Both `AUTHOR_SIGNATURE` and `SEAL_SIGNATURE` are non-zero |

A Sealed v2 artifact is considered immutable: any further edits invalidate
both signatures.

---

## Verification Flow (v2)

1. Read file (must be exactly 256 bytes for v2)
2. Parse and validate fields, confirm `VERSION == 2`
3. Verify `AUTHOR_SIGNATURE` over the author signing-bytes using
   `AUTHOR_PUBKEY`
4. If the companion `.vwh.note` file is available, compute
   `BLAKE3(note_file_bytes)` and compare to `NOTE_HASH`
5. Determine artifact state (Draft / Signed / Sealed)
6. If Sealed, verify `SEAL_SIGNATURE` over the seal signing-bytes using
   `SEAL_PUBKEY`
7. Optionally fetch registry status for `AUTHOR_PUBKEY` (as a `signing` key)
   and, if sealed, `SEAL_PUBKEY` (as a `sealing` key)

Signature verification (steps 3 and 6) and note hash verification (step 4) are
**authoritative and local**. Registry data (step 7) is **advisory only**.

A missing note file is not itself a verification failure — it is reported as
"note unavailable," distinct from "note hash mismatch" (which indicates
tampering or substitution).

---

## Registry (Optional)

Default registry base URL:

- `https://notvc.to/vwh-registry`

Registry data is versioned by path. Current tooling fetches the v2 endpoints:

- `/v2/keys.json`
- `/v2/ledger.json`

The v1 endpoints (`/v1/keys.json`, `/v1/ledger.json`) remain available for
historical/legacy lookups (Appendix A) but are not queried by default.

### v2/keys.json

```json
{
  "version": 2,
  "updated_at": "ISO8601",
  "keys": [
    {
      "fingerprint": "64-char hex (BLAKE3)",
      "public_key": "64-char hex (Ed25519)",
      "created_at": "ISO8601",
      "type": "signing|sealing",
      "status": "active|deprecated|revoked",
      "label": "optional string"
    }
  ]
}
```

The `type` field is new in v2 and indicates whether the key is a signing key
(used to produce `AUTHOR_SIGNATURE`) or a sealing key (used to produce
`SEAL_SIGNATURE`). A verifier checking registry status for `AUTHOR_PUBKEY`
should expect `type: "signing"`, and for `SEAL_PUBKEY`, `type: "sealing"`. A
mismatch (e.g. a `sealing`-typed key found in `AUTHOR_PUBKEY`) is advisory
information worth surfacing but does not by itself invalidate a signature.

### v2/ledger.json

```json
{
  "version": 2,
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

Semantics unchanged from v1: `active` means the artifact is publicly
acknowledged; `revoked` means explicitly revoked by the author, with
`revoked_at` and `reason` required.

---

## Trust Model

- **Authoritative:** local cryptographic verification of `AUTHOR_SIGNATURE`
  (and `SEAL_SIGNATURE` if sealed), and local note hash verification when the
  note file is available.
- **Advisory:** registry key status/type and public artifact acknowledgment.
- **Offline-first:** registry failures never invalidate a signature or note
  hash check.

---

## Notes

- V2 artifacts are immutable once sealed; any modification invalidates both
  signatures.
- The note file is part of an artifact's identity (via `NOTE_HASH`) but is
  distributed separately, keeping the binary artifact fixed-size.
- Signing and sealing keys are managed and stored separately by authoring
  tools, and tooling enforces that each key type is only usable for its
  corresponding operation.
- Future versions may extend the format while preserving v2 parsing rules for
  the fields defined here.

---

## Appendix A: V1 Format (Legacy, Historical)

**Status:** Deprecated. Preserved for IANA/registration history and for
parsing artifacts created before v2. Not actively verified by current
tooling; no new v1 artifacts should be created.

Binary layout (128 bytes total):

```
[ MAGIC        ]  4 bytes   "VWH\0"
[ VERSION      ]  2 bytes   u16 little-endian (= 1)
[ FLAGS        ]  1 byte    bitfield (bit 0 = SEALED)
[ ARTIFACT_ID  ] 16 bytes   random 128-bit identifier
[ TIMESTAMP    ]  8 bytes   u64 little-endian Unix seconds
[ INTENT       ]  1 byte    enum (0-4)
[ AUTHOR_PUBKEY] 32 bytes   Ed25519 public key
[ SIGNATURE    ] 64 bytes   Ed25519 signature
```

Signed bytes (in order): `MAGIC`, `VERSION`, `ARTIFACT_ID`, `TIMESTAMP`,
`INTENT`, `AUTHOR_PUBKEY` — i.e. all fields except `FLAGS` and `SIGNATURE`,
allowing the sealed flag to be toggled without re-signing.

V1 artifacts have no note file and no dual-signature model; `SEALED` is a
simple flag toggle, reversible only via `unsign` (full signature removal), not
`unseal`.