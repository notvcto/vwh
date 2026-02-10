pub mod crypto;
pub mod error;
pub mod format;
pub mod verify;

pub use error::{Error, Result};
pub use format::{Artifact, ArtifactState, FLAG_SEALED, MAGIC};

// ArtifactId, Intent, KeyFingerprint are defined in this module and exported below

use serde::{Deserialize, Serialize};
use std::fmt;

/// Artifact ID: immutable 128-bit random identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ArtifactId(pub [u8; 16]);

impl ArtifactId {
    pub fn new() -> Self {
        use rand::RngCore;
        let mut id = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut id);
        Self(id)
    }

    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s).map_err(|_| Error::InvalidHex)?;
        if bytes.len() != 16 {
            return Err(Error::InvalidArtifactId);
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Short display (first 8 bytes)
    pub fn short_display(&self) -> String {
        hex::encode(&self.0[..8])
    }
}

impl fmt::Display for ArtifactId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Default for ArtifactId {
    fn default() -> Self {
        Self::new()
    }
}

/// Intent enum (mandatory, no default)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Intent {
    Lab = 0,
    OwnedInfra = 1,
    AuthRedteam = 2,
    BlueRemediation = 3,
    Research = 4,
}

impl Intent {
    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Intent::Lab),
            1 => Ok(Intent::OwnedInfra),
            2 => Ok(Intent::AuthRedteam),
            3 => Ok(Intent::BlueRemediation),
            4 => Ok(Intent::Research),
            _ => Err(Error::InvalidIntent(value)),
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Intent::Lab => "LAB",
            Intent::OwnedInfra => "OWNED-INFRA",
            Intent::AuthRedteam => "AUTH-REDTEAM",
            Intent::BlueRemediation => "BLUE-REMEDIATION",
            Intent::Research => "RESEARCH",
        }
    }

    pub fn all() -> &'static [Intent] {
        &[
            Intent::Lab,
            Intent::OwnedInfra,
            Intent::AuthRedteam,
            Intent::BlueRemediation,
            Intent::Research,
        ]
    }

    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_uppercase().as_str() {
            "LAB" => Ok(Intent::Lab),
            "OWNED-INFRA" | "OWNED_INFRA" => Ok(Intent::OwnedInfra),
            "AUTH-REDTEAM" | "AUTH_REDTEAM" | "AUTHREDTEAM" => Ok(Intent::AuthRedteam),
            "BLUE-REMEDIATION" | "BLUE_REMEDIATION" => Ok(Intent::BlueRemediation),
            "RESEARCH" => Ok(Intent::Research),
            _ => Err(Error::InvalidIntentString(s.to_string())),
        }
    }
}

impl fmt::Display for Intent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Public key fingerprint (BLAKE3 hash of public key bytes)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyFingerprint(pub [u8; 32]);

impl KeyFingerprint {
    pub fn new(public_key_bytes: &[u8; 32]) -> Self {
        let hash = blake3::hash(public_key_bytes);
        Self(*hash.as_bytes())
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn short_display(&self) -> String {
        hex::encode(&self.0[..8])
    }
}

impl fmt::Display for KeyFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.short_display())
    }
}

/// Revocation reason
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum RevocationReason {
    Error,
    Compromised,
    Superseded,
    AccessRevoked,
    Other,
}

