use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;
use vwh_core::{format::Artifact, verify::verify_artifact};

const DEFAULT_REGISTRY_URL: &str = "https://notvc.to/data/vwh";

#[derive(Parser)]
#[command(name = "vwh")]
#[command(about = "VWH artifact inspector (PUBLIC)", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Inspect a .vwh artifact
    Inspect {
        /// Path to .vwh file
        file: PathBuf,
        
        /// Skip registry check (offline mode)
        #[arg(long)]
        offline: bool,
        
        /// Custom registry base URL
        #[arg(long, env = "VWH_REGISTRY_URL")]
        registry: Option<String>,
    },
}

// Registry data structures - forward-compatible with String enums
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct KeysRegistry {
    version: u32,
    updated_at: String,
    keys: Vec<KeyEntry>,
}

#[derive(Debug, Deserialize)]
struct KeyEntry {
    fingerprint: String,
    #[allow(dead_code)]
    public_key: String,
    created_at: String,
    #[allow(dead_code)]
    version: u32,
    label: Option<String>,
    revocation: Option<KeyRevocation>,
}

#[derive(Debug, Deserialize)]
struct KeyRevocation {
    revoked_at: String,
    reason: String,  // String for forward compatibility
    note: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RevocationsRegistry {
    #[allow(dead_code)]
    version: u32,
    updated_at: String,
    revocations: Vec<RevocationEntry>,
}

#[derive(Debug, Deserialize)]
struct RevocationEntry {
    artifact_id: String,
    revoked_at: String,
    reason: String,  // String for forward compatibility
    #[allow(dead_code)]
    key_fingerprint: String,
    note: Option<String>,
}

enum RegistryStatus {
    Available {
        keys: KeysRegistry,
        revocations: RevocationsRegistry,
    },
    Unavailable(String),
}

fn fetch_registry(base_url: &str, offline: bool) -> RegistryStatus {
    if offline {
        return RegistryStatus::Unavailable("Offline mode".to_string());
    }
    
    // Build HTTP client with strict settings
    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())  // No redirects for security
        .build()
    {
        Ok(c) => c,
        Err(e) => return RegistryStatus::Unavailable(format!("Failed to create HTTP client: {}", e)),
    };
    
    let base = base_url.trim_end_matches('/');
    let keys_url = format!("{}/keys.json", base);
    let revocations_url = format!("{}/revocations.json", base);
    
    // Fetch keys.json
    let keys = match client.get(&keys_url).send() {
        Ok(resp) => {
            if !resp.status().is_success() {
                return RegistryStatus::Unavailable(format!("HTTP {}: {}", resp.status(), keys_url));
            }
            match resp.json::<KeysRegistry>() {
                Ok(k) => k,
                Err(e) => return RegistryStatus::Unavailable(format!("Failed to parse keys.json: {}", e)),
            }
        }
        Err(e) => return RegistryStatus::Unavailable(format!("Failed to fetch keys.json: {}", e)),
    };
    
    // Fetch revocations.json
    let revocations = match client.get(&revocations_url).send() {
        Ok(resp) => {
            if !resp.status().is_success() {
                return RegistryStatus::Unavailable(format!("HTTP {}: {}", resp.status(), revocations_url));
            }
            match resp.json::<RevocationsRegistry>() {
                Ok(r) => r,
                Err(e) => return RegistryStatus::Unavailable(format!("Failed to parse revocations.json: {}", e)),
            }
        }
        Err(e) => return RegistryStatus::Unavailable(format!("Failed to fetch revocations.json: {}", e)),
    };
    
    RegistryStatus::Available { keys, revocations }
}

fn inspect(file: PathBuf, offline: bool, registry_url: Option<String>) -> Result<()> {
    println!("\n╭─────────────────────────────────────────╮");
    println!("│  VWH Artifact Inspector                 │");
    println!("╰─────────────────────────────────────────╯\n");
    
    // Read artifact
    let bytes = fs::read(&file)
        .with_context(|| format!("Failed to read file: {}", file.display()))?;
    
    println!("File: {}", file.display());
    println!("Size: {} bytes\n", bytes.len());
    
    // Parse artifact
    let artifact = Artifact::from_bytes(&bytes)
        .context("Failed to parse artifact")?;
    
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    println!("Artifact Information:\n");
    println!("  ID:          {}", artifact.artifact_id);
    println!("  Intent:      {}", artifact.intent);
    println!("  Created:     {}", artifact.timestamp.format("%Y-%m-%d %H:%M:%S UTC"));
    println!("  Version:     {}", artifact.version);
    println!("  Flags:       0x{:02x}", artifact.flags);
    println!("\n  Public Key:  {}", hex::encode(artifact.author_pubkey));
    println!("  Fingerprint: {}", artifact.author_fingerprint().to_hex());
    println!("  Short FP:    {}\n", artifact.author_fingerprint().short_display());
    
    // Verify signature
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    println!("Cryptographic Verification:\n");
    
    match verify_artifact(&artifact) {
        Ok(_) => {
            println!("  ✓ Signature valid");
            println!("  ✓ Artifact integrity verified\n");
        }
        Err(e) => {
            println!("  ✗ Signature INVALID: {}", e);
            println!("  ✗ Artifact may be corrupted or tampered\n");
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
            return Ok(());
        }
    }
    
    // Check registry
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    println!("Registry Status:\n");
    
    let base_url = registry_url.as_deref().unwrap_or(DEFAULT_REGISTRY_URL);
    let registry = fetch_registry(base_url, offline);
    
    match registry {
        RegistryStatus::Available { keys, revocations } => {
            println!("  ✓ Registry available");
            println!("  ✓ Last updated: {}\n", revocations.updated_at);
            
            // Check key status
            let fingerprint_hex = artifact.author_fingerprint().to_hex();
            let key_entry = keys.keys.iter().find(|k| k.fingerprint == fingerprint_hex);
            
            match key_entry {
                Some(key) => {
                    if let Some(ref revocation) = key.revocation {
                        println!("  ⚠  Signing key REVOKED");
                        println!("     Revoked: {}", revocation.revoked_at);
                        println!("     Reason:  {}", revocation.reason);
                        if let Some(ref note) = revocation.note {
                            println!("     Note:    {}", note);
                        }
                        println!();
                    } else {
                        println!("  ✓ Signing key recognized");
                        println!("     Created: {}", key.created_at);
                        if let Some(ref label) = key.label {
                            println!("     Label:   {}", label);
                        }
                        println!();
                    }
                }
                None => {
                    println!("  ⚠  Signing key not in registry");
                    println!("     This may be expected for new or private keys\n");
                }
            }
            
            // Check artifact revocation
            let artifact_id_hex = artifact.artifact_id.to_hex();
            let revocation_entry = revocations
                .revocations
                .iter()
                .find(|r| r.artifact_id == artifact_id_hex);
            
            match revocation_entry {
                Some(rev) => {
                    println!("  ⊗ Artifact REVOKED");
                    println!("     Revoked: {}", rev.revoked_at);
                    println!("     Reason:  {}", rev.reason);
                    if let Some(ref note) = rev.note {
                        println!("     Note:    {}", note);
                    }
                    println!("\n     Trust has been explicitly withdrawn for this artifact.\n");
                }
                None => {
                    println!("  ✓ Artifact not revoked\n");
                }
            }
        }
        RegistryStatus::Unavailable(reason) => {
            println!("  ⚠  Registry unavailable: {}", reason);
            println!("     Signature verification still valid");
            println!("     Revocation status unknown\n");
        }
    }
    
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Inspect { file, offline, registry } => inspect(file, offline, registry),
    }
}
