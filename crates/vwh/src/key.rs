use anyhow::{anyhow, Context, Result};
use argon2::{Argon2, ParamsBuilder, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use directories::BaseDirs;
use ed25519_dalek::SigningKey;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use vwh_core::KeyFingerprint;
use zeroize::Zeroizing;

pub fn decode_salt_for_kdf(version: u16, salt: &str) -> Result<Vec<u8>> {
    match version {
        2 => hex::decode(salt).context("Invalid salt in key file"),
        _ => Ok(salt.as_bytes().to_vec()),
    }
}

const KEY_FILENAME: &str = "identity.key.enc";
const PUBKEY_FILENAME: &str = "identity.pub";
const METADATA_FILENAME: &str = "metadata.json";

/// Key type for v2 separation of signing and sealing
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyType {
    Signing,
    Sealing,
}

impl std::fmt::Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyType::Signing => write!(f, "signing"),
            KeyType::Sealing => write!(f, "sealing"),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct KeyMetadata {
    pub key_type: KeyType,
    pub created_at: String,
    pub label: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedKeyFile {
    /// Argon2 salt (hex)
    pub salt: String,
    /// Nonce for ChaCha20Poly1305 (hex)
    pub nonce: String,
    /// Encrypted private key + tag (hex)
    pub ciphertext: String,
    /// Metadata
    pub version: u16,
    pub created_at: String,
}

/// VWH home: `~/.vwh`. Holds keys.json, ledger.json, the registry/ clone,
/// and the keys/ subtree.
pub fn get_config_dir() -> Result<PathBuf> {
    let base = BaseDirs::new()
        .ok_or_else(|| anyhow!("Could not determine home directory"))?;
    Ok(base.home_dir().join(".vwh"))
}

/// Directory holding per-key subdirectories: `~/.vwh/keys`.
pub fn get_keys_dir() -> Result<PathBuf> {
    Ok(get_config_dir()?.join("keys"))
}

/// Get path to a specific key directory: `~/.vwh/keys/<name>`.
pub fn get_key_dir(name: &str) -> Result<PathBuf> {
    Ok(get_keys_dir()?.join(name))
}

/// Generate auto key name based on timestamp
pub fn generate_key_name() -> String {
    let now = chrono::Utc::now();
    format!("key-{}", now.format("%Y%m%d-%H%M%S"))
}

/// Get key type from metadata file
pub fn get_key_type(name: &str) -> Result<KeyType> {
    let key_dir = get_key_dir(name)?;
    let metadata_file = key_dir.join(METADATA_FILENAME);
    
    if !metadata_file.exists() {
        // Legacy key without metadata - assume signing for backward compat
        return Ok(KeyType::Signing);
    }
    
    let metadata_json = fs::read_to_string(&metadata_file)
        .context("Failed to read metadata file")?;
    let metadata: KeyMetadata = serde_json::from_str(&metadata_json)
        .context("Failed to parse metadata")?;
    
    Ok(metadata.key_type)
}

/// Get key file path for a specific key
pub fn key_path_for(name: &str) -> Result<PathBuf> {
    // Special case: "legacy" refers to old single-key setup
    if name == "legacy" {
        return key_path();
    }
    Ok(get_key_dir(name)?.join(KEY_FILENAME))
}

/// Get pubkey file path for a specific key
fn pubkey_path_for(name: &str) -> Result<PathBuf> {
    // Special case: "legacy" refers to old single-key setup
    if name == "legacy" {
        return Ok(get_config_dir()?.join(PUBKEY_FILENAME));
    }
    Ok(get_key_dir(name)?.join(PUBKEY_FILENAME))
}

/// Legacy paths (for backward compatibility with existing single-key setups)
pub fn key_path() -> Result<PathBuf> {
    Ok(get_config_dir()?.join(KEY_FILENAME))
}

/// Resolve a user-supplied string (directory name or label) to an internal key directory name.
/// Tries exact directory name first, then falls back to label match in the registry.
pub fn resolve_key_name(input: &str) -> Result<String> {
    // Fast path: exact directory name
    if get_key_dir(input).map(|d| d.exists()).unwrap_or(false) {
        return Ok(input.to_string());
    }

    // Label match via registry
    let config_dir = get_config_dir()?;
    let keys_dir = get_keys_dir()?;
    let registry_mgr = crate::registry::RegistryManager::new(config_dir);
    let registry = registry_mgr.load_keys_v2()?;

    let input_lower = input.to_lowercase();
    for key in &registry.keys {
        if key.label.to_lowercase() == input_lower {
            // Find the directory for this fingerprint
            if let Ok(entries) = fs::read_dir(&keys_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        let pubkey_file = path.join("identity.pub");
                        if pubkey_file.exists() {
                            if let Ok(pubkey_hex) = fs::read_to_string(&pubkey_file) {
                                if let Ok(pubkey_bytes) = hex::decode(pubkey_hex.trim()) {
                                    if let Ok(arr) = TryInto::<[u8; 32]>::try_into(pubkey_bytes) {
                                        let fp = vwh_core::KeyFingerprint::new(&arr);
                                        if fp.to_hex() == key.fingerprint {
                                            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                                                return Ok(name.to_string());
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Err(anyhow!(
        "Key '{}' not found. Use a key directory name or label.\nRun 'vwh dump keys' to list available keys.",
        input
    ))
}

/// Find active key name from registry
pub fn get_active_key_name() -> Result<Option<String>> {
    use crate::registry::RegistryManager;
    
    let config_dir = get_config_dir()?;
    let registry_mgr = RegistryManager::new(config_dir);
    let keys_registry = registry_mgr.load_keys_v2()?;

    // Find first active key
    for key_entry in keys_registry.keys.iter() {
        if key_entry.status == "active" {
            // Find matching key directory
            let keys_dir = get_keys_dir()?;
            if let Ok(entries) = fs::read_dir(&keys_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        let pubkey_path = path.join(PUBKEY_FILENAME);
                        if pubkey_path.exists() {
                            if let Ok(pubkey_hex) = fs::read_to_string(&pubkey_path) {
                                if pubkey_hex.trim() == key_entry.public_key {
                                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                                        return Ok(Some(name.to_string()));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    // Fallback: check for legacy single-key setup
    let legacy_key = key_path()?;
    if legacy_key.exists() {
        return Ok(Some("legacy".to_string()));
    }
    
    Ok(None)
}

pub fn read_passphrase(prompt: &str) -> Result<Zeroizing<String>> {
    print!("{}", prompt);
    io::stdout().flush()?;
    
    let passphrase = rpassword::read_password()
        .context("Failed to read passphrase")?;
    
    Ok(Zeroizing::new(passphrase))
}

pub fn init(name: Option<String>, key_type: KeyType, label: Option<String>) -> Result<()> {
    let key_name = name.unwrap_or_else(generate_key_name);
    let label = Some(match label {
        Some(l) => l,
        None => crate::prompts::prompt_key_label(&key_type.to_string())?,
    });
    
    let config_dir = get_config_dir()?;
    let key_dir = get_key_dir(&key_name)?;
    let key_file = key_path_for(&key_name)?;
    let pubkey_file = pubkey_path_for(&key_name)?;
    let metadata_file = key_dir.join(METADATA_FILENAME);
    
    if key_file.exists() {
        return Err(anyhow!(
            "Key '{}' already exists at {}\nUse 'vwh key show {}' to view it.",
            key_name,
            key_file.display(),
            key_name
        ));
    }
    
    println!("\n== VWH Author Identity Initialization ==\n");
    
    println!("Creating key: {} ({})", key_name, key_type);
    println!();
    println!("This will generate a new Ed25519 keypair for {} artifacts.",
        if key_type == KeyType::Signing { "signing" } else { "sealing" });
    println!("The private key will be encrypted with a passphrase and stored at:\n");
    println!("  {}\n", key_file.display());
    println!("[WARN] This passphrase cannot be recovered. Write it down.\n");
    
    // Read passphrase
    let passphrase = read_passphrase("Enter passphrase: ")?;
    let passphrase_confirm = read_passphrase("Confirm passphrase: ")?;
    
    if *passphrase != *passphrase_confirm {
        return Err(anyhow!("Passphrases do not match"));
    }
    
    if passphrase.len() < 8 {
        return Err(anyhow!("Passphrase must be at least 8 characters"));
    }
    
    // Generate keypair
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let public_key_bytes = verifying_key.to_bytes();
    let private_key_bytes = Zeroizing::new(signing_key.to_bytes());

    // Calculate fingerprint
    let fingerprint = KeyFingerprint::new(&public_key_bytes);

    // Generate 16-byte binary salt; store as hex
    let mut salt_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut salt_bytes);
    let salt_hex = hex::encode(salt_bytes);

    // Derive encryption key using Argon2id
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        Version::V0x13,
        ParamsBuilder::new()
            .m_cost(65536) // 64 MiB
            .t_cost(3)
            .p_cost(4)
            .build()
            .unwrap(),
    );

    let mut key_bytes = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(passphrase.as_bytes(), &salt_bytes, &mut *key_bytes)
        .map_err(|e| anyhow!("Key derivation failed: {}", e))?;

    // Encrypt with ChaCha20Poly1305
    let cipher = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&*key_bytes));
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, private_key_bytes.as_ref())
        .map_err(|e| anyhow!("Encryption failed: {}", e))?;

    // Prepare encrypted key file
    let encrypted = EncryptedKeyFile {
        salt: salt_hex,
        nonce: hex::encode(nonce_bytes),
        ciphertext: hex::encode(&ciphertext),
        version: 2,
        created_at: chrono::Utc::now().to_rfc3339(),
    };
    
    // Write to disk
    fs::create_dir_all(&key_dir)
        .context("Failed to create key directory")?;
    
    let json = serde_json::to_string_pretty(&encrypted)?;
    fs::write(&key_file, json)
        .context("Failed to write encrypted key file")?;
    
    // Write public key (convenience)
    fs::write(&pubkey_file, hex::encode(public_key_bytes))
        .context("Failed to write public key file")?;
    
    // Write metadata
    let metadata = KeyMetadata {
        key_type,
        created_at: chrono::Utc::now().to_rfc3339(),
        label: label.clone(),
    };
    let metadata_json = serde_json::to_string_pretty(&metadata)?;
    fs::write(&metadata_file, metadata_json)
        .context("Failed to write metadata file")?;
    
    // Add key to local keys.json registry (v2 format with type)
    use crate::registry::{KeyEntryV2, RegistryManager};
    let registry_mgr = RegistryManager::new(config_dir.clone());
    let mut keys_registry = registry_mgr.load_keys_v2()?;
    
    keys_registry.add_key(KeyEntryV2 {
        fingerprint: fingerprint.to_hex(),
        public_key: hex::encode(public_key_bytes),
        created_at: chrono::Utc::now().to_rfc3339(),
        key_type: key_type.to_string(),
        status: "active".to_string(),
        label: label.as_deref().unwrap_or(&key_name).to_string(),
        deprecated_at: None,
        revoked_at: None,
        is_demo: None,
    });
    
    registry_mgr.save_keys_v2(&keys_registry)?;
    
    println!("\n✓ Keypair generated");
    println!("✓ Private key encrypted and saved");
    println!("✓ Public key saved");
    println!("✓ Metadata saved");
    println!("✓ Added to keys.json (v2)\n");
    println!("\n");
    println!("Identity created successfully.\n");
    println!("Label:       {}", label.as_deref().unwrap_or(&key_name));
    println!("Key type:    {}", key_type);
    println!("Public key:  {}", hex::encode(public_key_bytes));
    println!("Fingerprint: {} (short)\n", fingerprint.short_display());
    println!("Full fingerprint:");
    println!("{}\n", fingerprint.to_hex());
    println!("Run 'vwh key show {}' to view details.", key_name);
    
    Ok(())
}

pub fn show(name: Option<String>) -> Result<()> {
    let key_name = if let Some(n) = name {
        resolve_key_name(&n)?
    } else {
        get_active_key_name()?
            .ok_or_else(|| anyhow!("No active key found. Run 'vwh key init' first."))?
    };
    
    let key_file = key_path_for(&key_name)?;
    
    if !key_file.exists() {
        return Err(anyhow!(
            "Key '{}' not found. Run 'vwh key init {}' first.",
            key_name, key_name
        ));
    }
    
    let passphrase = read_passphrase("Enter passphrase: ")?;
    
    // Load and decrypt
    let json = fs::read_to_string(&key_file)
        .context("Failed to read key file")?;
    let encrypted: EncryptedKeyFile = serde_json::from_str(&json)
        .context("Failed to parse key file")?;
    
    // Derive decryption key
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        Version::V0x13,
        ParamsBuilder::new()
            .m_cost(65536)
            .t_cost(3)
            .p_cost(4)
            .build()
            .unwrap(),
    );

    let salt_raw = decode_salt_for_kdf(encrypted.version, &encrypted.salt)?;
    let mut key_bytes = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(
            passphrase.as_bytes(),
            &salt_raw,
            &mut *key_bytes,
        )
        .map_err(|e| anyhow!("Key derivation failed: {}", e))?;

    // Decrypt
    let cipher = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&*key_bytes));
    let nonce_bytes = hex::decode(&encrypted.nonce)
        .context("Invalid nonce in key file")?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = hex::decode(&encrypted.ciphertext)
        .context("Invalid ciphertext in key file")?;

    let plaintext = Zeroizing::new(
        cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|_| anyhow!("Decryption failed. Incorrect passphrase?"))?,
    );

    if plaintext.len() != 32 {
        return Err(anyhow!("Invalid private key length"));
    }

    let mut private_key_bytes = Zeroizing::new([0u8; 32]);
    private_key_bytes.copy_from_slice(&plaintext);

    let signing_key = SigningKey::from_bytes(&private_key_bytes);
    let public_key_bytes = signing_key.verifying_key().to_bytes();
    let fingerprint = KeyFingerprint::new(&public_key_bytes);
    
    // Get status from registry
    use crate::registry::RegistryManager;
    let config_dir = get_config_dir()?;
    let registry_mgr = RegistryManager::new(config_dir);
    let keys_registry = registry_mgr.load_keys_v2()?;

    let key_entry = keys_registry.keys.iter()
        .find(|k| k.fingerprint == fingerprint.to_hex());
    
    let status = key_entry.map(|k| k.status.as_str()).unwrap_or("unknown");
    
    println!("\n== Author Identity ==\n");
    println!("Key name: {}\n", key_name);
    println!("Public Key (hex):");
    println!("{}\n", hex::encode(public_key_bytes));
    println!("Fingerprint (BLAKE3):");
    println!("{}\n", fingerprint.to_hex());
    println!("Short fingerprint: {}\n", fingerprint.short_display());
    println!("Created:  {}", encrypted.created_at);
    println!("Version:  {}", encrypted.version);
    println!("Status:   {}\n", match status {
        "active" => "[OK] Active",
        "deprecated" => "[WARN] Deprecated",
        "revoked" => "[ERR] Revoked",
        _ => "[INFO] Unknown",
    });
    
    Ok(())
}

