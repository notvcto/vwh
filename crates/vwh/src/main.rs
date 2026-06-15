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
    deprecated_at: Option<String>,  // RFC3339, stamped on rotation
    revoked_at: Option<String>,     // RFC3339, stamped on revocation
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

fn fetch_registry(base_url: &str, offline: bool, artifact_version: u16) -> RegistryStatus {
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
    
    // Use versioned registry path
    let base = base_url.trim_end_matches('/');
    let registry_path = format!("{}/v{}", base, artifact_version);
    let keys_url = format!("{}/keys.json", registry_path);
    let ledger_url = format!("{}/ledger.json", registry_path);
    
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
    
    // Parse artifact
    let artifact = Artifact::from_bytes(&bytes)
        .context("Failed to parse artifact")?;
    
    print_sep();
    println!("Artifact Information:\n");
    println!("  ID:          {}", artifact.artifact_id);
    println!("  Intent:      {}", artifact.intent);
    println!("  Created:     {}", artifact.timestamp.format("%Y-%m-%d %H:%M:%S UTC"));
    println!("  Version:     {}", artifact.version.as_u16());
    
    // Display state with v2-aware descriptions
    let state = artifact.state();
    let state_str = match (&artifact.version, state) {
        (vwh_core::format::ArtifactVersion::V1, vwh_core::ArtifactState::Draft) => {
            if artifact.has_author_pubkey() {
                "DRAFT (unsigned, bound to key)"
            } else {
                "DRAFT (keyless)"
            }
        },
        (vwh_core::format::ArtifactVersion::V1, vwh_core::ArtifactState::Signed) => {
            "SIGNED (unsealed)"
        },
        (vwh_core::format::ArtifactVersion::V1, vwh_core::ArtifactState::Sealed) => {
            "SEALED"
        },
        (vwh_core::format::ArtifactVersion::V2, vwh_core::ArtifactState::Draft) => {
            "DRAFT (no author signature)"
        },
        (vwh_core::format::ArtifactVersion::V2, vwh_core::ArtifactState::Signed) => {
            "SIGNED (author only, not sealed)"
        },
        (vwh_core::format::ArtifactVersion::V2, vwh_core::ArtifactState::Sealed) => {
            "SEALED (dual-signed, immutable)"
        },
    };
    println!("  State:       {}", state_str);
    
    // V1-specific: show flags
    if artifact.version == vwh_core::format::ArtifactVersion::V1 {
        println!("  Flags:       0x{:02x}", artifact.flags);
        if artifact.is_sealed() {
            println!("  Sealed:      YES (immutable)");
        }
    }
    
    // Display keys based on version
    match artifact.version {
        vwh_core::format::ArtifactVersion::V1 => {
            if artifact.has_author_pubkey() {
                println!("\n  Public Key:  {}", hex::encode(artifact.author_pubkey));
                println!("  Fingerprint: {}", artifact.author_fingerprint().to_hex());
                println!("  Short FP:    {}\n", artifact.author_fingerprint().short_display());
            } else {
                println!("\n  Public Key:  (not bound to any key yet)");
                println!("  Fingerprint: (none)\n");
            }
        },
        vwh_core::format::ArtifactVersion::V2 => {
            // Author key
            if artifact.has_author_pubkey() {
                println!("\n  Author Key:  {}", hex::encode(artifact.author_pubkey));
                println!("  Author FP:   {}", artifact.author_fingerprint().to_hex());
            } else {
                println!("\n  Author Key:  (not bound to any key yet)");
                println!("  Author FP:   (none)");
            }
            
            // Seal key
            if let Some(seal_fp) = artifact.seal_fingerprint() {
                println!("  Seal Key:    {}", hex::encode(artifact.seal_pubkey));
                println!("  Seal FP:     {}", seal_fp.to_hex());
            } else {
                println!("  Seal Key:    (not sealed)");
                println!("  Seal FP:     (none)");
            }
            println!();
        },
    }
    
    // Note verification (V2 only)
    if artifact.version == vwh_core::format::ArtifactVersion::V2 {
        print_sep();
        println!("Note Verification:\n");
        
        if artifact.has_note_hash() {
            let note_path = file.with_extension("vwh.note");
            
            if note_path.exists() {
                match fs::read(&note_path) {
                    Ok(note_content) => {
                        let computed_hash = blake3::hash(&note_content);
                        if computed_hash.as_bytes() == &artifact.note_hash {
                            println!("  [OK] Note file found: {}", note_path.display());
                            println!("  [OK] Note hash verified (BLAKE3)");
                            println!("  [OK] Note integrity confirmed\n");
                        } else {
                            println!("  [ERR] Note file found but hash MISMATCH");
                            println!("       Expected: {}", hex::encode(artifact.note_hash));
                            println!("       Got:      {}", hex::encode(computed_hash.as_bytes()));
                            println!("  [ERR] Note may have been tampered with\n");
                        }
                    }
                    Err(e) => {
                        println!("  [ERR] Failed to read note file: {}", e);
                        println!("  [ERR] Cannot verify note integrity\n");
                    }
                }
            } else {
                println!("  [ERR] Note hash present but file NOT FOUND");
                println!("       Expected: {}", note_path.display());
                println!("  [ERR] This artifact is INVALID (missing required note)\n");
            }
        } else {
            println!("  [WARN] NO NOTE ATTACHED");
            println!("         Note hash is zero (edge case)");
            println!("         This should not happen in normal v2 workflow\n");
        }
    }
    
    // Verify signature
    print_sep();
    println!("Cryptographic Verification:\n");
    
    // Check SEAL flag consistency (V1) or dual signature (V2)
    if artifact.version == vwh_core::format::ArtifactVersion::V1 {
        if artifact.is_sealed() && !artifact.has_signature() {
            println!("  [ERR] INVALID: Artifact is sealed but unsigned");
            println!("  [ERR] This is a malformed artifact\n");
            return Ok(());
        }
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
    
    // Verify author signature
    match verify_artifact(&artifact) {
        Ok(_) => {
            println!("  [OK] Author signature valid");
            println!("  [OK] Artifact integrity verified");
            
            // V2: Check seal signature if present
            if artifact.version == vwh_core::format::ArtifactVersion::V2 && artifact.is_sealed() {
                // Verify seal signature
                use vwh_core::crypto::verify;
                let seal_bytes = artifact.seal_signing_bytes();
                match verify(&artifact.seal_pubkey, &seal_bytes, &artifact.seal_signature) {
                    Ok(_) => {
                        println!("  [OK] Seal signature valid");
                        println!("  [OK] DUAL-SIGNED (immutable)");
                    }
                    Err(e) => {
                        println!("  [ERR] Seal signature INVALID: {}", e);
                        println!("  [ERR] Artifact seal may be corrupted");
                        println!();
                        return Ok(());
                    }
                }
            } else if artifact.version == vwh_core::format::ArtifactVersion::V1 && artifact.is_sealed() {
                println!("  [OK] SEAL flag verified (artifact is immutable)");
            }
            
            println!();
        }
        Err(e) => {
            println!("  [ERR] Author signature INVALID: {}", e);
            println!("  [ERR] Artifact may be corrupted or tampered\n");
            return Ok(());
        }
    }
    
    // Check registry
    print_sep();
    println!("Registry Status:\n");
    
    let base_url = registry_url.as_deref().unwrap_or(DEFAULT_REGISTRY_URL);
    let artifact_version = artifact.version.as_u16();
    let registry = fetch_registry(base_url, offline, artifact_version);
    
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
                        if let Some(ref label) = key.label {
                            println!("     Label:   {}", label);
                        }
                        println!("     Created: {}", key.created_at);

                        match key.status.as_str() {
                            "active" => {
                                println!("  [OK] Signing key recognized (active)\n");
                            }
                            "deprecated" => {
                                match &key.deprecated_at {
                                    None => {
                                        println!("  [WARN] Signing key DEPRECATED");
                                        println!("     Rotation timestamp unavailable — cannot time-gate\n");
                                    }
                                    Some(dep_at) => {
                                        match chrono::DateTime::parse_from_rfc3339(dep_at) {
                                            Ok(dep_ts) => {
                                                if artifact.timestamp < dep_ts {
                                                    println!("  [OK] Signing key deprecated after signing — artifact valid");
                                                    println!("     Deprecated: {}\n", dep_at);
                                                } else {
                                                    println!("  [ERR] Artifact signed AFTER key was deprecated — INVALID");
                                                    println!("     Deprecated: {}\n", dep_at);
                                                }
                                            }
                                            Err(_) => {
                                                println!("  [WARN] Signing key DEPRECATED");
                                                println!("     Could not parse deprecation timestamp\n");
                                            }
                                        }
                                    }
                                }
                            }
                            "revoked" => {
                                match &key.revoked_at {
                                    None => {
                                        println!("  [WARN] Signing key REVOKED");
                                        println!("     Revocation timestamp unavailable — treat with caution\n");
                                    }
                                    Some(rev_at) => {
                                        match chrono::DateTime::parse_from_rfc3339(rev_at) {
                                            Ok(rev_ts) => {
                                                if artifact.timestamp < rev_ts {
                                                    println!("  [WARN] Signing key later revoked — artifact predates revocation");
                                                    println!("     Revoked: {}\n", rev_at);
                                                } else {
                                                    println!("  [ERR] Artifact signed AFTER key was revoked — INVALID");
                                                    println!("     Revoked: {}\n", rev_at);
                                                }
                                            }
                                            Err(_) => {
                                                println!("  [WARN] Signing key REVOKED");
                                                println!("     Could not parse revocation timestamp\n");
                                            }
                                        }
                                    }
                                }
                            }
                            _ => {
                                println!("  [WARN] Signing key has unknown status: {}\n", key.status);
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



