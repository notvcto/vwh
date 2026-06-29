use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use fd_lock::RwLock as FdLock;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};

/// Entry in keys.json (v2 - includes key type)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyEntryV2 {
    pub fingerprint: String,
    pub public_key: String,
    pub created_at: String,  // RFC3339
    #[serde(rename = "type")]
    pub key_type: String,    // "signing" | "sealing"
    pub status: String,      // "active" | "deprecated" | "revoked"
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deprecated_at: Option<String>,  // RFC3339, set on rotation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,     // RFC3339, set on explicit revoke
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_demo: Option<bool>,          // marks intentionally-published demo keys
}

/// keys.json structure (v2)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeysRegistryV2 {
    pub version: u32,
    pub updated_at: String,  // RFC3339
    pub keys: Vec<KeyEntryV2>,
}

impl KeysRegistryV2 {
    pub fn new() -> Self {
        Self {
            version: 2,
            updated_at: Utc::now().to_rfc3339(),
            keys: Vec::new(),
        }
    }

    pub fn add_key(&mut self, entry: KeyEntryV2) {
        self.keys.push(entry);
        self.updated_at = Utc::now().to_rfc3339();
    }

    pub fn find_key_mut(&mut self, fingerprint: &str) -> Option<&mut KeyEntryV2> {
        self.keys.iter_mut().find(|k| k.fingerprint == fingerprint)
    }

    pub fn mark_deprecated(&mut self, fingerprint: &str) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let key = self.find_key_mut(fingerprint)
            .context("Key not found in registry")?;
        key.status = "deprecated".to_string();
        key.deprecated_at = Some(now.clone());
        self.updated_at = now;
        Ok(())
    }

    pub fn mark_revoked(&mut self, fingerprint: &str) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let key = self.find_key_mut(fingerprint)
            .context("Key not found in registry")?;
        key.status = "revoked".to_string();
        key.revoked_at = Some(now.clone());
        self.updated_at = now;
        Ok(())
    }

    pub fn get_active_keys(&self) -> Vec<&KeyEntryV2> {
        self.keys.iter()
            .filter(|k| k.status == "active")
            .collect()
    }

    pub fn get_signing_keys(&self) -> Vec<&KeyEntryV2> {
        self.keys.iter()
            .filter(|k| k.status == "active" && k.key_type == "signing")
            .collect()
    }

    pub fn get_sealing_keys(&self) -> Vec<&KeyEntryV2> {
        self.keys.iter()
            .filter(|k| k.status == "active" && k.key_type == "sealing")
            .collect()
    }
}

/// Entry in ledger.json (for artifacts)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerEntry {
    pub id: String,
    pub fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,  // RFC3339; None for entries created before this field existed
    pub status: String,              // "active" | "revoked"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// ledger.json structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerRegistry {
    pub version: u32,
    pub updated_at: String,  // RFC3339
    pub artifacts: Vec<LedgerEntry>,
}

impl LedgerRegistry {
    pub fn new() -> Self {
        Self {
            version: 1,
            updated_at: Utc::now().to_rfc3339(),
            artifacts: Vec::new(),
        }
    }

    pub fn add_or_update_artifact(&mut self, entry: LedgerEntry) {
        if let Some(existing) = self.artifacts.iter_mut().find(|a| a.id == entry.id) {
            *existing = entry;
        } else {
            self.artifacts.push(entry);
        }
        self.updated_at = Utc::now().to_rfc3339();
    }

    pub fn get_artifact(&self, artifact_id: &str) -> Option<&LedgerEntry> {
        self.artifacts.iter().find(|a| a.id == artifact_id)
    }
}

/// Write data to path atomically via a .tmp sibling file.
fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, data)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

/// Open (or create) a file and return an fd-lock guard for exclusive access.
///
/// This handle exists ONLY to hold the advisory lock; the actual write goes
/// through `atomic_write` (tmp + rename). Do NOT add `.truncate(true)` here —
/// it would zero the registry on every lock acquisition.
#[allow(clippy::suspicious_open_options)]
fn lock_registry_exclusive(path: &Path) -> Result<FdLock<std::fs::File>> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)?;
    Ok(FdLock::new(file))
}

/// Open an existing file and return an fd-lock guard for shared read access.
fn lock_registry_shared(path: &Path) -> Result<FdLock<std::fs::File>> {
    let file = OpenOptions::new()
        .read(true)
        .open(path)?;
    Ok(FdLock::new(file))
}

/// Registry manager for local registry files
pub struct RegistryManager {
    config_dir: PathBuf,
}

impl RegistryManager {
    pub fn new(config_dir: PathBuf) -> Self {
        Self { config_dir }
    }

    pub fn keys_path(&self) -> PathBuf {
        self.config_dir.join("keys.json")
    }

    pub fn ledger_path(&self) -> PathBuf {
        self.config_dir.join("ledger.json")
    }

    /// Load keys.json v2 (with key types), creating if doesn't exist
    pub fn load_keys_v2(&self) -> Result<KeysRegistryV2> {
        let path = self.keys_path();
        if !path.exists() {
            return Ok(KeysRegistryV2::new());
        }

        let lock = lock_registry_shared(&path)?;
        let _guard = lock.read()?;
        let json = fs::read_to_string(&path)
            .context("Failed to read keys.json")?;
        let registry: KeysRegistryV2 = serde_json::from_str(&json)
            .context("Failed to parse keys.json v2")?;

        if registry.version != 2 {
            return Err(anyhow!(
                "Expected keys registry version 2, got {}",
                registry.version
            ));
        }

        Ok(registry)
    }

    /// Save keys.json v2
    pub fn save_keys_v2(&self, registry: &KeysRegistryV2) -> Result<()> {
        fs::create_dir_all(&self.config_dir)?;
        let json = serde_json::to_string_pretty(registry)?;
        let path = self.keys_path();
        let mut lock = lock_registry_exclusive(&path)?;
        let _guard = lock.write()?;
        atomic_write(&path, json.as_bytes())?;
        Ok(())
    }

    /// Load ledger.json, creating if doesn't exist
    pub fn load_ledger(&self) -> Result<LedgerRegistry> {
        let path = self.ledger_path();
        if !path.exists() {
            return Ok(LedgerRegistry::new());
        }

        let lock = lock_registry_shared(&path)?;
        let _guard = lock.read()?;
        let json = fs::read_to_string(&path)
            .context("Failed to read ledger.json")?;
        let registry: LedgerRegistry = serde_json::from_str(&json)
            .context("Failed to parse ledger.json")?;

        if registry.version != 1 {
            return Err(anyhow!(
                "Expected ledger registry version 1, got {}",
                registry.version
            ));
        }

        Ok(registry)
    }

    /// Save ledger.json
    pub fn save_ledger(&self, registry: &LedgerRegistry) -> Result<()> {
        fs::create_dir_all(&self.config_dir)?;
        let json = serde_json::to_string_pretty(registry)?;
        let path = self.ledger_path();
        let mut lock = lock_registry_exclusive(&path)?;
        let _guard = lock.write()?;
        atomic_write(&path, json.as_bytes())?;
        Ok(())
    }
}
