use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;
use vwh_core::{format::Artifact, verify::verify_artifact};

const DEFAULT_REGISTRY_URL: &str = "https://notvc.to/vwh-registry";
const SECTION_SEP: &str = "-----------------------------------------";

fn print_sep() {
    println!("{}\n", SECTION_SEP);
}


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

// Registry data structures - v1 format
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
    status: String,  // "active" | "deprecated" | "revoked"
    label: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LedgerRegistry {
    #[allow(dead_code)]
    version: u32,
    updated_at: String,
    artifacts: Vec<LedgerEntry>,
}

#[derive(Debug, Deserialize)]
struct LedgerEntry {
    id: String,
    fingerprint: String,
    status: String, // "active" | "revoked"
    revoked_at: Option<String>,
    reason: Option<String>,
}

enum RegistryStatus {
    Available {
        keys: KeysRegistry,
        ledger: LedgerRegistry,
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
    let ledger_url = format!("{}/ledger.json", base);
    
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
    
    // Fetch ledger.json
    let ledger = match client.get(&ledger_url).send() {
        Ok(resp) => {
            if !resp.status().is_success() {
                return RegistryStatus::Unavailable(format!("HTTP {}: {}", resp.status(), ledger_url));
            }
            match resp.json::<LedgerRegistry>() {
                Ok(r) => r,
                Err(e) => return RegistryStatus::Unavailable(format!("Failed to parse ledger.json: {}", e)),
            }
        }
        Err(e) => return RegistryStatus::Unavailable(format!("Failed to fetch ledger.json: {}", e)),
    };
    
    RegistryStatus::Available { keys, ledger }
}

fn inspect(file: PathBuf, offline: bool, registry_url: Option<String>) -> Result<()> {
    println!("\n== VWH Artifact Inspector ==\n");
    
    // Read artifact
    let bytes = fs::read(&file)
        .with_context(|| format!("Failed to read file: {}", file.display()))?;
    
    println!("File: {}", file.display());
    println!("Size: {} bytes\n", bytes.len());
    
    // Parse artifact (with v2 detection)
    let artifact = match Artifact::from_bytes(&bytes) {
        Ok(art) => art,
        Err(vwh_core::Error::UnsupportedVersion(2)) => {
            print_sep();
            println!("VWH v2 Format Detected\n");
            println!("  This artifact uses the VWH v2 format (256 bytes).");
            println!("  This inspector only supports VWH v1 (128 bytes).\n");
            println!("  To inspect v2 artifacts, please upgrade to vwh v2.x:");
            println!("  cargo install vwh --version ^2.0\n");
            print_sep();
            return Ok(());
        },
        Err(vwh_core::Error::UnsupportedVersion(ver)) => {
            anyhow::bail!("Unsupported VWH version: {}", ver);
        },
        Err(e) => return Err(e).context("Failed to parse artifact"),
    };
    
    print_sep();
    println!("Artifact Information:\n");
    println!("  ID:          {}", artifact.artifact_id);
    println!("  Intent:      {}", artifact.intent);
    println!("  Created:     {}", artifact.timestamp.format("%Y-%m-%d %H:%M:%S UTC"));
    println!("  Version:     {}", artifact.version);
    println!("  Flags:       0x{:02x}", artifact.flags);
    
    // Display state
    let state = artifact.state();
    let state_str = match state {
        vwh_core::ArtifactState::Draft => {
            if artifact.has_author_pubkey() {
                "DRAFT (unsigned, bound to key)"
            } else {
                "DRAFT (keyless)"
            }
        },
        vwh_core::ArtifactState::Signed => "SIGNED (unsealed)",
        vwh_core::ArtifactState::Sealed => "SEALED",
    };
    println!("  State:       {}", state_str);
    
    if artifact.is_sealed() {
        println!("  Sealed:      YES (immutable)");
    }
    
    if artifact.has_author_pubkey() {
        println!("\n  Public Key:  {}", hex::encode(artifact.author_pubkey));
        println!("  Fingerprint: {}", artifact.author_fingerprint().to_hex());
        println!("  Short FP:    {}\n", artifact.author_fingerprint().short_display());
    } else {
        println!("\n  Public Key:  (not bound to any key yet)");
        println!("  Fingerprint: (none)\n");
    }
    
    // Verify signature
    print_sep();
    println!("Cryptographic Verification:\n");
    
    // Check SEAL flag consistency
    if artifact.is_sealed() && !artifact.has_signature() {
        println!("  [ERR] INVALID: Artifact is sealed but unsigned");
        println!("  [ERR] This is a malformed artifact\n");
        return Ok(());
    }
    
    if !artifact.has_signature() {
        if artifact.has_author_pubkey() {
            println!("  [INFO] Artifact is unsigned but bound to a key");
            println!("  [INFO] Can only be signed with the bound key");
        } else {
            println!("  [INFO] Artifact is keyless (not bound to any key)");
            println!("  [INFO] Can be signed with any key");
        }
        println!("  [INFO] No signature to verify\n");
        return Ok(());
    }
    
    match verify_artifact(&artifact) {
        Ok(_) => {
            println!("  [OK] Signature valid");
            println!("  [OK] Artifact integrity verified");
            if artifact.is_sealed() {
                println!("  [OK] SEAL flag verified (artifact is immutable)");
            }
            println!();
        }
        Err(e) => {
            println!("  [ERR] Signature INVALID: {}", e);
            println!("  [ERR] Artifact may be corrupted or tampered\n");
            return Ok(());
        }
    }
    
    // Check registry
    print_sep();
    println!("Registry Status:\n");
    
    let base_url = registry_url.as_deref().unwrap_or(DEFAULT_REGISTRY_URL);
    let registry = fetch_registry(base_url, offline);
    
    match registry {
        RegistryStatus::Available { keys, ledger } => {
            println!("  [OK] Registry available");
            println!("  [OK] Last updated: {}\n", ledger.updated_at);
            
            // Check key status
            if artifact.has_author_pubkey() {
                let fingerprint_hex = artifact.author_fingerprint().to_hex();
                let key_entry = keys.keys.iter().find(|k| k.fingerprint == fingerprint_hex);
                
                match key_entry {
                    Some(key) => {
                        match key.status.as_str() {
                            "revoked" => {
                                println!("  [WARN] Signing key REVOKED");
                                println!("     Created: {}", key.created_at);
                                if let Some(ref label) = key.label {
                                    println!("     Label:   {}", label);
                                }
                                println!("     Key is revoked in the registry\n");
                            }
                            "deprecated" => {
                                println!("  [WARN] Signing key DEPRECATED");
                                println!("     Created: {}", key.created_at);
                                if let Some(ref label) = key.label {
                                    println!("     Label:   {}", label);
                                }
                                println!("     Key has been rotated but remains valid\n");
                            }
                            "active" => {
                                println!("  [OK] Signing key recognized (active)");
                                println!("     Created: {}", key.created_at);
                                if let Some(ref label) = key.label {
                                    println!("     Label:   {}", label);
                                }
                                println!();
                            }
                            _ => {
                                println!("  [WARN] Signing key has unknown status: {}", key.status);
                                println!();
                            }
                        }
                    }
                    None => {
                        println!("  [INFO] Signing key not in registry");
                        println!("     This may be expected for new or private keys\n");
                    }
                }
            } else {
                println!("  [INFO] Signing key not set (keyless draft)\n");
            }
            
            // Check artifact ledger status
            let artifact_id_hex = artifact.artifact_id.to_hex();
            let ledger_entry = ledger
                .artifacts
                .iter()
                .find(|a| a.id == artifact_id_hex);
            
            match ledger_entry {
                Some(entry) => {
                    // If we have a pubkey, ensure ledger fingerprint matches artifact author fingerprint
                    if artifact.has_author_pubkey() {
                        let artifact_fp = artifact.author_fingerprint().to_hex();
                        if entry.fingerprint != artifact_fp {
                            println!("  [WARN] Ledger fingerprint mismatch");
                            println!("     Ledger:   {}", entry.fingerprint);
                            println!("     Artifact: {}\n", artifact_fp);
                        }
                    }
                    match entry.status.as_str() {
                        "revoked" => {
                            println!("  [REVOKED] Artifact REVOKED");
                            if let Some(ref revoked_at) = entry.revoked_at {
                                println!("     Revoked: {}", revoked_at);
                            }
                            if let Some(ref reason) = entry.reason {
                                println!("     Reason:  {}", reason);
                            }
                            println!("\n     Trust has been explicitly withdrawn for this artifact.\n");
                        }
                        "active" => {
                            if artifact.is_sealed() {
                                println!("  [OK] VERIFIED");
                                println!("     Signed, Sealed, and Publicly Acknowledged.\n");
                            } else {
                                println!("  [OK] VERIFIED");
                                println!("     Local file is Draft, but ID is confirmed in public ledger.\n");
                            }
                        }
                        _ => {
                            println!("  [WARN] Artifact has unknown ledger status: {}", entry.status);
                            println!();
                        }
                    }
                }
                None => {
                    if artifact.is_sealed() {
                        println!("  [WARN] SUSPICIOUS");
                        println!("     File claims to be Sealed, but is NOT in public ledger.");
                        println!("     Possible tampering or embargo.\n");
                    } else {
                        println!("  [WARN] UNPUBLISHED");
                        println!("     Valid signature. Draft state. Not publicly acknowledged.\n");
                    }
                }
            }
        }
        RegistryStatus::Unavailable(reason) => {
            println!("  [WARN] Registry unavailable: {}", reason);
            println!("     Signature verification still valid");
            println!("     Ledger status unknown\n");
        }
    }
    
    
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::Inspect { file, offline, registry } => inspect(file, offline, registry),
    }
}



