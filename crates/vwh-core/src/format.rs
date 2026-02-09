use crate::{ArtifactId, Error, Intent, KeyFingerprint, Result};
use chrono::{DateTime, TimeZone, Utc};
use std::io::{Read, Write};

pub const MAGIC: &[u8; 4] = b"VWH\0";
pub const VERSION: u16 = 1;
pub const MIN_ARTIFACT_SIZE: usize = 4 + 2 + 1 + 16 + 8 + 1 + 32 + 64; // 128 bytes

/// Complete artifact structure
#[derive(Debug, Clone)]
pub struct Artifact {
    pub version: u16,
    pub flags: u8,
    pub artifact_id: ArtifactId,
    pub timestamp: DateTime<Utc>,
    pub intent: Intent,
    pub author_pubkey: [u8; 32],
    pub signature: [u8; 64],
}

impl Artifact {
    /// Parse artifact from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < MIN_ARTIFACT_SIZE {
            return Err(Error::FileTooSmall {
                expected: MIN_ARTIFACT_SIZE,
                actual: bytes.len(),
            });
        }

        let mut cursor = 0;

        // Magic (4 bytes)
        let magic = &bytes[cursor..cursor + 4];
        if magic != MAGIC {
            return Err(Error::InvalidMagic);
        }
        cursor += 4;

        // Version (2 bytes, little-endian)
        let version = u16::from_le_bytes([bytes[cursor], bytes[cursor + 1]]);
        if version != VERSION {
            return Err(Error::UnsupportedVersion(version));
        }
        cursor += 2;

        // Flags (1 byte)
        let flags = bytes[cursor];
        cursor += 1;

        // Artifact ID (16 bytes)
        let mut artifact_id_bytes = [0u8; 16];
        artifact_id_bytes.copy_from_slice(&bytes[cursor..cursor + 16]);
        let artifact_id = ArtifactId::from_bytes(artifact_id_bytes);
        cursor += 16;

        // Timestamp (8 bytes, little-endian, Unix timestamp)
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

        // Signature (64 bytes) - last field
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&bytes[cursor..cursor + 64]);

        Ok(Artifact {
            version,
            flags,
            artifact_id,
            timestamp,
            intent,
            author_pubkey,
            signature,
        })
    }

    /// Get bytes that were signed (everything before signature)
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(MIN_ARTIFACT_SIZE - 64);

        // Magic
        bytes.extend_from_slice(MAGIC);

        // Version (LE)
        bytes.extend_from_slice(&self.version.to_le_bytes());

        // Flags
        bytes.push(self.flags);

        // Artifact ID
        bytes.extend_from_slice(&self.artifact_id.0);

        // Timestamp (LE)
        bytes.extend_from_slice(&(self.timestamp.timestamp() as u64).to_le_bytes());

        // Intent
        bytes.push(self.intent.to_u8());

        // Author public key
        bytes.extend_from_slice(&self.author_pubkey);

        bytes
    }

    /// Serialize artifact to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.signing_bytes();
        bytes.extend_from_slice(&self.signature);
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
}

/// Builder for creating new artifacts
pub struct ArtifactBuilder {
    artifact_id: ArtifactId,
    timestamp: DateTime<Utc>,
    intent: Intent,
    author_pubkey: [u8; 32],
    flags: u8,
}

impl ArtifactBuilder {
    pub fn new(intent: Intent, author_pubkey: [u8; 32]) -> Self {
        Self {
            artifact_id: ArtifactId::new(),
            timestamp: Utc::now(),
            intent,
            author_pubkey,
            flags: 0,
        }
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

    /// Build unsigned artifact (for signing)
    pub fn build_unsigned(&self) -> UnsignedArtifact {
        UnsignedArtifact {
            version: VERSION,
            flags: self.flags,
            artifact_id: self.artifact_id,
            timestamp: self.timestamp,
            intent: self.intent,
            author_pubkey: self.author_pubkey,
        }
    }
}

/// Unsigned artifact (before signing)
pub struct UnsignedArtifact {
    pub version: u16,
    pub flags: u8,
    pub artifact_id: ArtifactId,
    pub timestamp: DateTime<Utc>,
    pub intent: Intent,
    pub author_pubkey: [u8; 32],
}

impl UnsignedArtifact {
    /// Get bytes to sign
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(MIN_ARTIFACT_SIZE - 64);

        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.push(self.flags);
        bytes.extend_from_slice(&self.artifact_id.0);
        bytes.extend_from_slice(&(self.timestamp.timestamp() as u64).to_le_bytes());
        bytes.push(self.intent.to_u8());
        bytes.extend_from_slice(&self.author_pubkey);

        bytes
    }

    /// Attach signature and create complete artifact
    pub fn with_signature(self, signature: [u8; 64]) -> Artifact {
        Artifact {
            version: self.version,
            flags: self.flags,
            artifact_id: self.artifact_id,
            timestamp: self.timestamp,
            intent: self.intent,
            author_pubkey: self.author_pubkey,
            signature,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_artifact_roundtrip() {
        let artifact_id = ArtifactId::new();
        let timestamp = Utc::now();
        let intent = Intent::Lab;
        let author_pubkey = [42u8; 32];
        let signature = [99u8; 64];

        let artifact = Artifact {
            version: VERSION,
            flags: 0,
            artifact_id,
            timestamp,
            intent,
            author_pubkey,
            signature,
        };

        let bytes = artifact.to_bytes();
        let parsed = Artifact::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.version, artifact.version);
        assert_eq!(parsed.artifact_id, artifact.artifact_id);
        assert_eq!(parsed.intent, artifact.intent);
        assert_eq!(parsed.author_pubkey, artifact.author_pubkey);
        assert_eq!(parsed.signature, artifact.signature);
    }

    #[test]
    fn test_invalid_magic() {
        let mut bytes = vec![0u8; MIN_ARTIFACT_SIZE];
        bytes[0..4].copy_from_slice(b"NOPE");
        assert!(matches!(
            Artifact::from_bytes(&bytes),
            Err(Error::InvalidMagic)
        ));
    }

    #[test]
    fn test_file_too_small() {
        let bytes = vec![0u8; 10];
        assert!(matches!(
            Artifact::from_bytes(&bytes),
            Err(Error::FileTooSmall { .. })
        ));
    }
}
