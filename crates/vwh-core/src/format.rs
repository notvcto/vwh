use crate::{ArtifactId, Error, Intent, KeyFingerprint, Result};
use chrono::{DateTime, TimeZone, Utc};
use std::io::{Read, Write};

pub const MAGIC: &[u8; 4] = b"VWH\0";
pub const VERSION_V1: u16 = 1;
pub const VERSION_V2: u16 = 2;
pub const ARTIFACT_SIZE_V1: usize = 128;
pub const ARTIFACT_SIZE_V2: usize = 256;

// V1 FLAGS byte bit definitions
pub const FLAG_SEALED: u8 = 0b00000001;

// Zero markers
pub const ZERO_PUBKEY: [u8; 32] = [0u8; 32];
pub const ZERO_HASH: [u8; 32] = [0u8; 32];
pub const ZERO_SIGNATURE: [u8; 64] = [0u8; 64];

/// Artifact version
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactVersion {
    V1,
    V2,
}

impl std::fmt::Display for ArtifactVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArtifactVersion::V1 => write!(f, "v1"),
            ArtifactVersion::V2 => write!(f, "v2"),
        }
    }
}

impl ArtifactVersion {
    pub fn as_u16(&self) -> u16 {
        match self {
            ArtifactVersion::V1 => VERSION_V1,
            ArtifactVersion::V2 => VERSION_V2,
        }
    }
    
    pub fn from_u16(v: u16) -> Result<Self> {
        match v {
            VERSION_V1 => Ok(ArtifactVersion::V1),
            VERSION_V2 => Ok(ArtifactVersion::V2),
            _ => Err(Error::UnsupportedVersion(v)),
        }
    }
}

/// Artifact state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactState {
    /// V1: Unsigned draft | V2: No author signature
    Draft,
    /// V1: Signed but not sealed | V2: Author signed but not sealed
    Signed,
    /// V1: Sealed (FLAGS bit set) | V2: Dual-signed (author + seal)
    Sealed,
}

/// Complete artifact structure (supports both v1 and v2)
#[derive(Debug, Clone)]
pub struct Artifact {
    pub version: ArtifactVersion,
    
    // Common fields (present in both v1 and v2)
    pub artifact_id: ArtifactId,
    pub timestamp: DateTime<Utc>,
    pub intent: Intent,
    pub author_pubkey: [u8; 32],
    pub author_signature: [u8; 64],
    
    // V1-specific fields
    pub flags: u8,  // Only used in v1
    
    // V2-specific fields
    pub reserved_a: u8,
    pub note_hash: [u8; 32],
    pub seal_pubkey: [u8; 32],
    pub seal_signature: [u8; 64],
}

impl Artifact {
    /// Parse artifact from bytes (auto-detects v1 vs v2)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // Check minimum size for magic + version
        if bytes.len() < 6 {
            return Err(Error::FileTooSmall { expected: 6, actual: bytes.len() });
        }
        
        // Check magic
        if &bytes[0..4] != MAGIC {
            return Err(Error::InvalidMagic);
        }
        
        // Read version
        let version_u16 = u16::from_le_bytes([bytes[4], bytes[5]]);
        let version = ArtifactVersion::from_u16(version_u16)?;
        
        match version {
            ArtifactVersion::V1 => Self::from_bytes_v1(bytes),
            ArtifactVersion::V2 => Self::from_bytes_v2(bytes),
        }
    }
    
    /// Parse v1 artifact (128 bytes)
    fn from_bytes_v1(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != ARTIFACT_SIZE_V1 {
            return Err(Error::FileTooSmall {
                expected: ARTIFACT_SIZE_V1,
                actual: bytes.len(),
            });
        }

        let mut cursor = 0;

        // Magic (4 bytes) - already validated
        cursor += 4;

        // Version (2 bytes) - already validated
        cursor += 2;

        // Flags (1 byte)
        let flags = bytes[cursor];
        cursor += 1;

        // Artifact ID (16 bytes)
        let mut artifact_id_bytes = [0u8; 16];
        artifact_id_bytes.copy_from_slice(&bytes[cursor..cursor + 16]);
        let artifact_id = ArtifactId::from_bytes(artifact_id_bytes);
        cursor += 16;

        // Timestamp (8 bytes, little-endian)
        let timestamp_secs =
            u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap());
        let timestamp = Utc
            .timestamp_opt(timestamp_secs as i64, 0)
            .single()
            .ok_or_else(|| Error::UnexpectedEof {
                field: "timestamp".to_string(),
            })?;
        cursor += 8;

        // Intent (1 byte)
        let intent = Intent::from_u8(bytes[cursor])?;
        cursor += 1;

        // Author public key (32 bytes)
        let mut author_pubkey = [0u8; 32];
        author_pubkey.copy_from_slice(&bytes[cursor..cursor + 32]);
        cursor += 32;

        // Signature (64 bytes)
        let mut author_signature = [0u8; 64];
        author_signature.copy_from_slice(&bytes[cursor..cursor + 64]);

        Ok(Artifact {
            version: ArtifactVersion::V1,
            artifact_id,
            timestamp,
            intent,
            author_pubkey,
            author_signature,
            flags,
            reserved_a: 0,
            note_hash: ZERO_HASH,
            seal_pubkey: ZERO_PUBKEY,
            seal_signature: ZERO_SIGNATURE,
        })
    }
    
    /// Parse v2 artifact (256 bytes)
    fn from_bytes_v2(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != ARTIFACT_SIZE_V2 {
            return Err(Error::FileTooSmall {
                expected: ARTIFACT_SIZE_V2,
                actual: bytes.len(),
            });
        }

        let mut cursor = 0;

        // Magic (4 bytes) - already validated
        cursor += 4;

        // Version (2 bytes) - already validated
        cursor += 2;

        // RESERVED_A (1 byte)
        let reserved_a = bytes[cursor];
        cursor += 1;

        // Artifact ID (16 bytes)
        let mut artifact_id_bytes = [0u8; 16];
        artifact_id_bytes.copy_from_slice(&bytes[cursor..cursor + 16]);
        let artifact_id = ArtifactId::from_bytes(artifact_id_bytes);
        cursor += 16;

        // Timestamp (8 bytes, little-endian)
        let timestamp_secs =
            u64::from_le_bytes(bytes[cursor..cursor + 8].try_into().unwrap());
        let timestamp = Utc
            .timestamp_opt(timestamp_secs as i64, 0)
            .single()
            .ok_or_else(|| Error::UnexpectedEof {
                field: "timestamp".to_string(),
            })?;
        cursor += 8;

        // Intent (1 byte)
        let intent = Intent::from_u8(bytes[cursor])?;
        cursor += 1;

        // Author public key (32 bytes)
        let mut author_pubkey = [0u8; 32];
        author_pubkey.copy_from_slice(&bytes[cursor..cursor + 32]);
        cursor += 32;

        // NOTE_HASH (32 bytes)
        let mut note_hash = [0u8; 32];
        note_hash.copy_from_slice(&bytes[cursor..cursor + 32]);
        cursor += 32;

        // AUTHOR_SIGNATURE (64 bytes)
        let mut author_signature = [0u8; 64];
        author_signature.copy_from_slice(&bytes[cursor..cursor + 64]);
        cursor += 64;

        // SEAL_PUBKEY (32 bytes)
        let mut seal_pubkey = [0u8; 32];
        seal_pubkey.copy_from_slice(&bytes[cursor..cursor + 32]);
        cursor += 32;

        // SEAL_SIGNATURE (64 bytes)
        let mut seal_signature = [0u8; 64];
        seal_signature.copy_from_slice(&bytes[cursor..cursor + 64]);

        Ok(Artifact {
            version: ArtifactVersion::V2,
            artifact_id,
            timestamp,
            intent,
            author_pubkey,
            author_signature,
            flags: 0,
            reserved_a,
            note_hash,
            seal_pubkey,
            seal_signature,
        })
    }

    /// Get bytes that were signed by author
    pub fn author_signing_bytes(&self) -> Vec<u8> {
        match self.version {
            ArtifactVersion::V1 => {
                // V1: 63 bytes (FLAGS excluded)
                let mut bytes = Vec::with_capacity(63);
                bytes.extend_from_slice(MAGIC);
                bytes.extend_from_slice(&VERSION_V1.to_le_bytes());
                // FLAGS NOT INCLUDED (it's state, not identity)
                bytes.extend_from_slice(&self.artifact_id.0);
                bytes.extend_from_slice(&(self.timestamp.timestamp() as u64).to_le_bytes());
                bytes.push(self.intent.to_u8());
                bytes.extend_from_slice(&self.author_pubkey);
                bytes
            },
            ArtifactVersion::V2 => {
                // V2: 103 bytes (everything before author_signature)
                let mut bytes = Vec::with_capacity(103);
                bytes.extend_from_slice(MAGIC);  // 4
                bytes.extend_from_slice(&VERSION_V2.to_le_bytes());  // 2
                bytes.push(self.reserved_a);  // 1
                bytes.extend_from_slice(&self.artifact_id.0);  // 16
                bytes.extend_from_slice(&(self.timestamp.timestamp() as u64).to_le_bytes());  // 8
                bytes.push(self.intent.to_u8());  // 1
                bytes.extend_from_slice(&self.author_pubkey);  // 32
                bytes.extend_from_slice(&self.note_hash);  // 32
                bytes
            },
        }
    }
    
    /// Get bytes that were signed by seal (V2 only)
    pub fn seal_signing_bytes(&self) -> Vec<u8> {
        assert_eq!(self.version, ArtifactVersion::V2, "seal_signing_bytes only valid for v2");
        
        // 192 bytes: everything except seal_signature
        let mut bytes = Vec::with_capacity(192);
        bytes.extend_from_slice(MAGIC);  // 4
        bytes.extend_from_slice(&VERSION_V2.to_le_bytes());  // 2
        bytes.push(self.reserved_a);  // 1
        bytes.extend_from_slice(&self.artifact_id.0);  // 16
        bytes.extend_from_slice(&(self.timestamp.timestamp() as u64).to_le_bytes());  // 8
        bytes.push(self.intent.to_u8());  // 1
        bytes.extend_from_slice(&self.author_pubkey);  // 32
        bytes.extend_from_slice(&self.note_hash);  // 32
        bytes.extend_from_slice(&self.author_signature);  // 64
        bytes.extend_from_slice(&self.seal_pubkey);  // 32
        bytes
    }

    /// Get bytes for signing (legacy compatibility)
    pub fn signing_bytes(&self) -> Vec<u8> {
        self.author_signing_bytes()
    }

    /// Serialize artifact to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        match self.version {
            ArtifactVersion::V1 => self.to_bytes_v1(),
            ArtifactVersion::V2 => self.to_bytes_v2(),
        }
    }
    
    fn to_bytes_v1(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(ARTIFACT_SIZE_V1);
        
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION_V1.to_le_bytes());
        bytes.push(self.flags);
        bytes.extend_from_slice(&self.artifact_id.0);
        bytes.extend_from_slice(&(self.timestamp.timestamp() as u64).to_le_bytes());
        bytes.push(self.intent.to_u8());
        bytes.extend_from_slice(&self.author_pubkey);
        bytes.extend_from_slice(&self.author_signature);
        
        bytes
    }
    
    fn to_bytes_v2(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(ARTIFACT_SIZE_V2);
        
        bytes.extend_from_slice(MAGIC);  // 4
        bytes.extend_from_slice(&VERSION_V2.to_le_bytes());  // 2
        bytes.push(self.reserved_a);  // 1
        bytes.extend_from_slice(&self.artifact_id.0);  // 16
        bytes.extend_from_slice(&(self.timestamp.timestamp() as u64).to_le_bytes());  // 8
        bytes.push(self.intent.to_u8());  // 1
        bytes.extend_from_slice(&self.author_pubkey);  // 32
        bytes.extend_from_slice(&self.note_hash);  // 32
        bytes.extend_from_slice(&self.author_signature);  // 64
        bytes.extend_from_slice(&self.seal_pubkey);  // 32
        bytes.extend_from_slice(&self.seal_signature);  // 64
        
        bytes
    }

    /// Write artifact to a writer
    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.to_bytes())?;
        Ok(())
    }

    /// Read artifact from a reader
    pub fn read_from<R: Read>(reader: &mut R) -> Result<Self> {
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes)?;
        Self::from_bytes(&bytes)
    }

    /// Get author key fingerprint
    pub fn author_fingerprint(&self) -> KeyFingerprint {
        KeyFingerprint::new(&self.author_pubkey)
    }
    
    /// Get seal key fingerprint (V2 only)
    pub fn seal_fingerprint(&self) -> Option<KeyFingerprint> {
        if self.version == ArtifactVersion::V2 && self.seal_pubkey != ZERO_PUBKEY {
            Some(KeyFingerprint::new(&self.seal_pubkey))
        } else {
            None
        }
    }
    
    /// Check if artifact is sealed
    /// V1: FLAGS bit set | V2: Seal signature present
    pub fn is_sealed(&self) -> bool {
        match self.version {
            ArtifactVersion::V1 => (self.flags & FLAG_SEALED) != 0,
            ArtifactVersion::V2 => self.seal_signature != ZERO_SIGNATURE,
        }
    }
    
    /// Check if artifact has author signature
    pub fn has_author_signature(&self) -> bool {
        self.author_signature != ZERO_SIGNATURE
    }
    
    /// Check if artifact has a signature (legacy compatibility)
    pub fn has_signature(&self) -> bool {
        self.has_author_signature()
    }
    
    /// Check if artifact has an author public key (keyless draft = all zeros)
    pub fn has_author_pubkey(&self) -> bool {
        self.author_pubkey != ZERO_PUBKEY
    }
    
    /// Check if note hash is present (V2 only)
    pub fn has_note_hash(&self) -> bool {
        self.version == ArtifactVersion::V2 && self.note_hash != ZERO_HASH
    }
    
    /// Determine artifact state
    pub fn state(&self) -> ArtifactState {
        if !self.has_author_signature() {
            ArtifactState::Draft
        } else if self.is_sealed() {
            ArtifactState::Sealed
        } else {
            ArtifactState::Signed
        }
    }
    
    /// Set seal flag (V1 only - returns new artifact with flag set)
    pub fn with_seal_flag(mut self) -> Self {
        if self.version == ArtifactVersion::V1 {
            self.flags |= FLAG_SEALED;
        }
        self
    }
    
    /// Clear seal flag (V1 only - returns new artifact with flag cleared)
    pub fn without_seal_flag(mut self) -> Self {
        if self.version == ArtifactVersion::V1 {
            self.flags &= !FLAG_SEALED;
        }
        self
    }
    
    /// Remove author signature
    pub fn without_author_signature(mut self) -> Self {
        self.author_signature = ZERO_SIGNATURE;
        self
    }
    
    /// Remove signature (legacy compatibility)
    pub fn without_signature(self) -> Self {
        self.without_author_signature()
    }
    
    /// Remove seal signature (V2 only)
    pub fn without_seal_signature(mut self) -> Self {
        if self.version == ArtifactVersion::V2 {
            self.seal_signature = ZERO_SIGNATURE;
            self.seal_pubkey = ZERO_PUBKEY;
        }
        self
    }
    
    /// Add seal signature (V2 only)
    pub fn with_seal(mut self, seal_pubkey: [u8; 32], seal_signature: [u8; 64]) -> Self {
        if self.version == ArtifactVersion::V2 {
            self.seal_pubkey = seal_pubkey;
            self.seal_signature = seal_signature;
        }
        self
    }
}

/// Builder for creating new artifacts
pub struct ArtifactBuilder {
    version: ArtifactVersion,
    artifact_id: ArtifactId,
    timestamp: DateTime<Utc>,
    intent: Intent,
    author_pubkey: [u8; 32],
    flags: u8,  // V1 only
    note_hash: [u8; 32],  // V2 only
}

impl ArtifactBuilder {
    /// Create v1 artifact builder
    pub fn new_v1(intent: Intent, author_pubkey: [u8; 32]) -> Self {
        Self {
            version: ArtifactVersion::V1,
            artifact_id: ArtifactId::new(),
            timestamp: Utc::now(),
            intent,
            author_pubkey,
            flags: 0,
            note_hash: ZERO_HASH,
        }
    }
    
    /// Create v2 artifact builder
    pub fn new_v2(intent: Intent, author_pubkey: [u8; 32], note_hash: [u8; 32]) -> Self {
        Self {
            version: ArtifactVersion::V2,
            artifact_id: ArtifactId::new(),
            timestamp: Utc::now(),
            intent,
            author_pubkey,
            flags: 0,
            note_hash,
        }
    }
    
    /// Create artifact builder (defaults to v1 for backward compatibility)
    pub fn new(intent: Intent, author_pubkey: [u8; 32]) -> Self {
        Self::new_v1(intent, author_pubkey)
    }

    pub fn with_artifact_id(mut self, id: ArtifactId) -> Self {
        self.artifact_id = id;
        self
    }

    pub fn with_timestamp(mut self, timestamp: DateTime<Utc>) -> Self {
        self.timestamp = timestamp;
        self
    }

    pub fn with_flags(mut self, flags: u8) -> Self {
        self.flags = flags;
        self
    }
    
    pub fn with_note_hash(mut self, note_hash: [u8; 32]) -> Self {
        self.note_hash = note_hash;
        self
    }

    /// Build unsigned artifact (for signing)
    pub fn build_unsigned(&self) -> UnsignedArtifact {
        UnsignedArtifact {
            version: self.version,
            flags: self.flags,
            artifact_id: self.artifact_id,
            timestamp: self.timestamp,
            intent: self.intent,
            author_pubkey: self.author_pubkey,
            note_hash: self.note_hash,
        }
    }
}

/// Unsigned artifact (before signing)
pub struct UnsignedArtifact {
    pub version: ArtifactVersion,
    pub flags: u8,  // V1 only
    pub artifact_id: ArtifactId,
    pub timestamp: DateTime<Utc>,
    pub intent: Intent,
    pub author_pubkey: [u8; 32],
    pub note_hash: [u8; 32],  // V2 only
}

impl UnsignedArtifact {
    /// Get bytes to sign (author signature)
    pub fn author_signing_bytes(&self) -> Vec<u8> {
        match self.version {
            ArtifactVersion::V1 => {
                // V1: 63 bytes (FLAGS excluded)
                let mut bytes = Vec::with_capacity(63);
                bytes.extend_from_slice(MAGIC);
                bytes.extend_from_slice(&VERSION_V1.to_le_bytes());
                // FLAGS NOT INCLUDED
                bytes.extend_from_slice(&self.artifact_id.0);
                bytes.extend_from_slice(&(self.timestamp.timestamp() as u64).to_le_bytes());
                bytes.push(self.intent.to_u8());
                bytes.extend_from_slice(&self.author_pubkey);
                bytes
            },
            ArtifactVersion::V2 => {
                // V2: 103 bytes
                let mut bytes = Vec::with_capacity(103);
                bytes.extend_from_slice(MAGIC);
                bytes.extend_from_slice(&VERSION_V2.to_le_bytes());
                bytes.push(0u8);  // reserved_a
                bytes.extend_from_slice(&self.artifact_id.0);
                bytes.extend_from_slice(&(self.timestamp.timestamp() as u64).to_le_bytes());
                bytes.push(self.intent.to_u8());
                bytes.extend_from_slice(&self.author_pubkey);
                bytes.extend_from_slice(&self.note_hash);
                bytes
            },
        }
    }
    
    /// Get bytes to sign (legacy compatibility)
    pub fn signing_bytes(&self) -> Vec<u8> {
        self.author_signing_bytes()
    }

    /// Attach author signature and create complete artifact
    pub fn with_author_signature(self, signature: [u8; 64]) -> Artifact {
        Artifact {
            version: self.version,
            artifact_id: self.artifact_id,
            timestamp: self.timestamp,
            intent: self.intent,
            author_pubkey: self.author_pubkey,
            author_signature: signature,
            flags: self.flags,
            reserved_a: 0,
            note_hash: self.note_hash,
            seal_pubkey: ZERO_PUBKEY,
            seal_signature: ZERO_SIGNATURE,
        }
    }
    
    /// Attach signature (legacy compatibility)
    pub fn with_signature(self, signature: [u8; 64]) -> Artifact {
        self.with_author_signature(signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crypto, Intent};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn make_author_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn make_seal_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    // --- V1 roundtrip ---

    #[test]
    fn test_v1_roundtrip() {
        let author_key = make_author_key();
        let author_pubkey = author_key.verifying_key().to_bytes();

        let unsigned = ArtifactBuilder::new_v1(Intent::Lab, author_pubkey).build_unsigned();
        let sig = crypto::sign(&author_key, &unsigned.author_signing_bytes());
        let artifact = unsigned.with_signature(sig);

        let parsed = Artifact::from_bytes(&artifact.to_bytes()).unwrap();

        assert_eq!(parsed.version, ArtifactVersion::V1);
        assert_eq!(parsed.artifact_id, artifact.artifact_id);
        assert_eq!(parsed.intent, artifact.intent);
        assert_eq!(parsed.author_pubkey, artifact.author_pubkey);
        assert_eq!(parsed.author_signature, artifact.author_signature);
        assert_eq!(parsed.flags, artifact.flags);
    }

    // --- V2 roundtrip ---

    #[test]
    fn test_v2_roundtrip_unsigned() {
        let author_key = make_author_key();
        let author_pubkey = author_key.verifying_key().to_bytes();
        let note_hash = [0xabu8; 32];

        let unsigned = ArtifactBuilder::new_v2(Intent::Lab, author_pubkey, note_hash).build_unsigned();
        let sig = crypto::sign(&author_key, &unsigned.author_signing_bytes());
        let artifact = unsigned.with_signature(sig);

        let parsed = Artifact::from_bytes(&artifact.to_bytes()).unwrap();

        assert_eq!(parsed.version, ArtifactVersion::V2);
        assert_eq!(parsed.artifact_id, artifact.artifact_id);
        assert_eq!(parsed.intent, artifact.intent);
        assert_eq!(parsed.author_pubkey, artifact.author_pubkey);
        assert_eq!(parsed.author_signature, artifact.author_signature);
        assert_eq!(parsed.note_hash, note_hash);
        assert_eq!(parsed.seal_pubkey, ZERO_PUBKEY);
        assert_eq!(parsed.seal_signature, ZERO_SIGNATURE);
    }

    #[test]
    fn test_v2_roundtrip_sealed() {
        let author_key = make_author_key();
        let seal_key = make_seal_key();
        let author_pubkey = author_key.verifying_key().to_bytes();
        let seal_pubkey = seal_key.verifying_key().to_bytes();
        let note_hash = [0xbcu8; 32];

        let unsigned = ArtifactBuilder::new_v2(Intent::Lab, author_pubkey, note_hash).build_unsigned();
        let author_sig = crypto::sign(&author_key, &unsigned.author_signing_bytes());
        let author_signed = unsigned.with_signature(author_sig);

        let pre_seal = author_signed.with_seal(seal_pubkey, [0u8; 64]);
        let seal_sig = crypto::sign(&seal_key, &pre_seal.seal_signing_bytes());
        let sealed = pre_seal.with_seal(seal_pubkey, seal_sig);

        let parsed = Artifact::from_bytes(&sealed.to_bytes()).unwrap();

        assert_eq!(parsed.version, ArtifactVersion::V2);
        assert_eq!(parsed.note_hash, note_hash);
        assert_eq!(parsed.author_pubkey, author_pubkey);
        assert_eq!(parsed.author_signature, sealed.author_signature);
        assert_eq!(parsed.seal_pubkey, seal_pubkey);
        assert_eq!(parsed.seal_signature, sealed.seal_signature);
        // Verify seal signature actually validates (not just stored correctly)
        assert!(crypto::verify(&seal_pubkey, &parsed.seal_signing_bytes(), &parsed.seal_signature).is_ok());
    }

    // --- State machine ---

    #[test]
    fn test_v2_state_draft() {
        let author_key = make_author_key();
        let author_pubkey = author_key.verifying_key().to_bytes();
        let unsigned = ArtifactBuilder::new_v2(Intent::Lab, author_pubkey, ZERO_HASH).build_unsigned();
        let artifact = unsigned.with_signature(ZERO_SIGNATURE);
        assert_eq!(artifact.state(), ArtifactState::Draft);
        assert!(!artifact.has_author_signature());
        assert!(!artifact.is_sealed());
    }

    #[test]
    fn test_v2_state_signed() {
        let author_key = make_author_key();
        let author_pubkey = author_key.verifying_key().to_bytes();
        let unsigned = ArtifactBuilder::new_v2(Intent::Lab, author_pubkey, ZERO_HASH).build_unsigned();
        let sig = crypto::sign(&author_key, &unsigned.author_signing_bytes());
        let artifact = unsigned.with_signature(sig);

        assert_eq!(artifact.state(), ArtifactState::Signed);
        assert!(artifact.has_author_signature());
        assert!(!artifact.is_sealed());
    }

    #[test]
    fn test_v2_state_sealed() {
        let author_key = make_author_key();
        let seal_key = make_seal_key();
        let author_pubkey = author_key.verifying_key().to_bytes();
        let seal_pubkey = seal_key.verifying_key().to_bytes();

        let unsigned = ArtifactBuilder::new_v2(Intent::Lab, author_pubkey, ZERO_HASH).build_unsigned();
        let author_sig = crypto::sign(&author_key, &unsigned.author_signing_bytes());
        let author_signed = unsigned.with_signature(author_sig);
        let pre_seal = author_signed.with_seal(seal_pubkey, [0u8; 64]);
        let seal_sig = crypto::sign(&seal_key, &pre_seal.seal_signing_bytes());
        let sealed = pre_seal.with_seal(seal_pubkey, seal_sig);

        assert_eq!(sealed.state(), ArtifactState::Sealed);
        assert!(sealed.has_author_signature());
        assert!(sealed.is_sealed());
    }

    // --- Signature binding ---

    #[test]
    fn test_v2_author_sig_covers_note_hash() {
        let author_key = make_author_key();
        let author_pubkey = author_key.verifying_key().to_bytes();
        let note_hash = [0x11u8; 32];

        let unsigned = ArtifactBuilder::new_v2(Intent::Lab, author_pubkey, note_hash).build_unsigned();
        let sig = crypto::sign(&author_key, &unsigned.author_signing_bytes());
        let mut artifact = unsigned.with_signature(sig);
        artifact.note_hash = [0x22u8; 32]; // tamper

        let verify_bytes = artifact.author_signing_bytes();
        assert!(crypto::verify(&author_pubkey, &verify_bytes, &artifact.author_signature).is_err());
    }

    #[test]
    fn test_v2_seal_sig_covers_author_sig() {
        let author_key = make_author_key();
        let seal_key = make_seal_key();
        let author_pubkey = author_key.verifying_key().to_bytes();
        let seal_pubkey = seal_key.verifying_key().to_bytes();

        let unsigned = ArtifactBuilder::new_v2(Intent::Lab, author_pubkey, ZERO_HASH).build_unsigned();
        let author_sig = crypto::sign(&author_key, &unsigned.author_signing_bytes());
        let author_signed = unsigned.with_signature(author_sig);
        let pre_seal = author_signed.with_seal(seal_pubkey, [0u8; 64]);
        let seal_sig = crypto::sign(&seal_key, &pre_seal.seal_signing_bytes());
        let mut sealed = pre_seal.with_seal(seal_pubkey, seal_sig);
        sealed.author_signature = [0xffu8; 64]; // tamper

        let verify_bytes = sealed.seal_signing_bytes();
        assert!(crypto::verify(&seal_pubkey, &verify_bytes, &sealed.seal_signature).is_err());
    }

    #[test]
    fn test_v2_seal_key_can_differ_from_author_key() {
        let author_key = make_author_key();
        let seal_key = make_seal_key();
        assert_ne!(
            author_key.verifying_key().to_bytes(),
            seal_key.verifying_key().to_bytes()
        );
    }

    // --- Unsign/unseal ---

    #[test]
    fn test_v2_without_author_signature() {
        let author_key = make_author_key();
        let author_pubkey = author_key.verifying_key().to_bytes();
        let unsigned = ArtifactBuilder::new_v2(Intent::Lab, author_pubkey, ZERO_HASH).build_unsigned();
        let sig = crypto::sign(&author_key, &unsigned.author_signing_bytes());
        let artifact = unsigned.with_signature(sig).without_author_signature();

        assert_eq!(artifact.author_signature, ZERO_SIGNATURE);
        assert_eq!(artifact.state(), ArtifactState::Draft);
    }

    #[test]
    fn test_v2_without_seal_signature() {
        let author_key = make_author_key();
        let seal_key = make_seal_key();
        let author_pubkey = author_key.verifying_key().to_bytes();
        let seal_pubkey = seal_key.verifying_key().to_bytes();

        let unsigned = ArtifactBuilder::new_v2(Intent::Lab, author_pubkey, ZERO_HASH).build_unsigned();
        let author_sig = crypto::sign(&author_key, &unsigned.author_signing_bytes());
        let author_signed = unsigned.with_signature(author_sig);
        let pre_seal = author_signed.with_seal(seal_pubkey, [0u8; 64]);
        let seal_sig = crypto::sign(&seal_key, &pre_seal.seal_signing_bytes());
        let sealed = pre_seal.with_seal(seal_pubkey, seal_sig);
        let unsealed = sealed.without_seal_signature();

        assert_eq!(unsealed.seal_signature, ZERO_SIGNATURE);
        assert_eq!(unsealed.seal_pubkey, ZERO_PUBKEY);
        assert_eq!(unsealed.state(), ArtifactState::Signed);
        assert!(unsealed.has_author_signature());
    }

    // --- Parse errors ---

    #[test]
    fn test_invalid_magic() {
        let mut bytes = vec![0u8; ARTIFACT_SIZE_V1];
        bytes[0..4].copy_from_slice(b"NOPE");
        assert!(matches!(Artifact::from_bytes(&bytes), Err(Error::InvalidMagic)));
    }

    #[test]
    fn test_file_too_small() {
        let bytes = vec![0u8; 5]; // below 6-byte minimum for magic+version
        assert!(matches!(Artifact::from_bytes(&bytes), Err(Error::FileTooSmall { .. })));
    }

    #[test]
    fn test_v1_wrong_size_rejected() {
        let mut bytes = vec![0u8; ARTIFACT_SIZE_V1 - 1];
        bytes[0..4].copy_from_slice(MAGIC);
        bytes[4..6].copy_from_slice(&VERSION_V1.to_le_bytes());
        assert!(Artifact::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_v2_wrong_size_rejected() {
        let mut bytes = vec![0u8; ARTIFACT_SIZE_V2 - 1];
        bytes[0..4].copy_from_slice(MAGIC);
        bytes[4..6].copy_from_slice(&VERSION_V2.to_le_bytes());
        assert!(Artifact::from_bytes(&bytes).is_err());
    }
}

