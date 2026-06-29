use anyhow::{anyhow, bail, Context, Result};
use argon2::{Argon2, ParamsBuilder, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use chrono::Utc;
use ed25519_dalek::SigningKey;
use std::fs;
use std::path::PathBuf;
use vwh_core::{crypto, format::{Artifact, ArtifactBuilder, ArtifactVersion, ZERO_PUBKEY}, Intent};
use zeroize::Zeroizing;

use crate::key::{decode_salt_for_kdf, EncryptedKeyFile, get_config_dir, get_key_type, read_passphrase, KeyType};
use crate::registry::{
    KeyEntryV2, LedgerEntry, RegistryManager,
};
use crate::state;

pub(crate) fn build_argon2() -> Result<Argon2<'static>> {
    let params = ParamsBuilder::new()
        .m_cost(65536)
        .t_cost(3)
        .p_cost(4)
        .build()
        .map_err(|e| anyhow!("Failed to build Argon2 params: {}", e))?;
    Ok(Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params))
}

/// Create unsigned draft artifact
pub fn create_draft(
    intent_str: String,
    output: PathBuf,
    use_v1: bool,
) -> Result<()> {
    // Check if output file already exists
    if output.exists() {
        return Err(anyhow!(
            "File already exists: {}\nArtifacts are immutable and cannot be overwritten.",
            output.display()
        ));
    }

    // Parse intent
    let intent = Intent::from_str(&intent_str).context(
        "Invalid intent. Valid values: lab, owned-infra, auth-redteam, blue-remediation, research",
    )?;

    let artifact = if use_v1 {
        // V1: No note needed (legacy format)
        use console::Style;
        let yellow = Style::new().yellow();
        println!();
        println!("{}", yellow.apply_to("[V1 Format] Creating legacy 128-byte artifact (no note)"));
        println!();
        
        let builder = ArtifactBuilder::new_v1(intent, ZERO_PUBKEY);
        let unsigned = builder.build_unsigned();
        unsigned.with_author_signature([0u8; 64]) // Zero signature = unsigned
    } else {
        // V2: Interactive note prompt (REQUIRED)
        use console::Style;
        let cyan = Style::new().cyan();
        println!();
        println!("{}", cyan.apply_to("[V2 Format] Creating 256-byte artifact with detached note"));
        
        let body = crate::prompts::prompt_note()?;

        // Stamp the artifact's registry into the note header so inspectors know
        // which registry to consult. The whole note (header + body) is hashed.
        let registry = crate::note_meta::registry_for_new_note();
        let note = crate::note_meta::note_with_registry(&registry, &body);

        // Compute note hash
        let note_hash = blake3::hash(note.as_bytes());

        // Build v2 artifact
        let builder = ArtifactBuilder::new_v2(
            intent,
            ZERO_PUBKEY,
            *note_hash.as_bytes()
        );
        let unsigned = builder.build_unsigned();
        let artifact = unsigned.with_author_signature([0u8; 64]); // Zero signature = unsigned

        // Write note file
        let note_path = output.with_extension("vwh.note");
        fs::write(&note_path, &note)
            .context("Failed to write note file")?;
        
        artifact
    };

    let _draft = state::require_typed_draft(artifact.clone())?;

    // Write to disk
    let artifact_bytes = artifact.to_bytes();
    fs::write(&output, &artifact_bytes).context("Failed to write artifact file")?;

    // Show success with nice formatting
    let details = vec![
        ("File", output.display().to_string()),
        ("Size", format!("{} bytes", artifact_bytes.len())),
        ("ID", artifact.artifact_id.short_display()),
        ("Intent", artifact.intent.to_string()),
        ("Version", artifact.version.as_u16().to_string()),
        ("State", "DRAFT (unsigned)".to_string()),
    ];
    
    crate::prompts::print_success_box("Artifact Created", &details);

    // Next steps
    use console::Style;
    let dim = Style::new().dim();
    println!("{}", dim.apply_to("Next steps:"));
    if use_v1 {
        println!("  {} vwh sign {}", dim.apply_to("1."), output.display());
        println!("  {} vwh seal {}", dim.apply_to("2."), output.display());
    } else {
        println!("  {} vwh sign {} --key <signing-key>", dim.apply_to("1."), output.display());
        println!("  {} vwh seal {} --key <sealing-key>", dim.apply_to("2."), output.display());
    }
    println!();

    Ok(())
}

/// Sign an unsigned draft artifact
pub fn sign(file: PathBuf, key_name_opt: Option<String>) -> Result<()> {
    // Load artifact
    let bytes = fs::read(&file).context("Failed to read artifact file")?;
    let mut artifact = Artifact::from_bytes(&bytes).context("Failed to parse artifact")?;

    // Validate state
    state::require_draft(&artifact)?;
    let _draft = state::require_typed_draft(artifact.clone())?;

    // Get key to use
    let key_name = if let Some(name) = key_name_opt {
        let resolved = crate::key::resolve_key_name(&name)?;
        use console::Style;
        let cyan = Style::new().cyan();
        println!("{}", cyan.apply_to(format!("Using specified key: {}", resolved)));
        println!();
        resolved
    } else {
        // V2: Use interactive key selector for signing keys
        if artifact.version == ArtifactVersion::V2 {
            let config_dir = get_config_dir()?;
            let registry_mgr = RegistryManager::new(config_dir);
            let registry = registry_mgr.load_keys_v2()?;
            let signing_keys: Vec<KeyEntryV2> = registry.get_signing_keys().into_iter().cloned().collect();

            crate::prompts::select_key(&signing_keys, "signing")?
        } else {
            // V1: Use active key fallback
            crate::key::get_active_key_name()?
                .ok_or_else(|| anyhow!("No active key found. Run 'vwh key init --type signing' first."))?
        }
    };
    
    // V2: Enforce key type - only signing keys can sign
    if artifact.version == ArtifactVersion::V2 {
        let key_type = get_key_type(&key_name)?;
        if key_type != KeyType::Signing {
            bail!(
                "Cannot sign with {} key '{}'\n\n\
                 Signing requires a signing key.\n\
                 Sealing keys can only be used for the seal command.\n\n\
                 Create a signing key with: vwh key init --type signing",
                key_type, key_name
            );
        }
    }
    
    let key_file = crate::key::key_path_for(&key_name)?;
    if !key_file.exists() {
        return Err(anyhow!("Key '{}' not found. Run 'vwh key init --type signing {}' first.", key_name, key_name));
    }

    let passphrase = read_passphrase("Enter passphrase: ")?;

    // Decrypt private key
    let json = fs::read_to_string(&key_file)?;
    let encrypted: EncryptedKeyFile = serde_json::from_str(&json)?;

    let argon2 = build_argon2()?;

    let salt_raw = decode_salt_for_kdf(encrypted.version, &encrypted.salt)?;
    let mut key_bytes = Zeroizing::new([0u8; 32]);
    argon2.hash_password_into(passphrase.as_bytes(), &salt_raw, &mut *key_bytes)
        .map_err(|e| anyhow!("Key derivation failed: {}", e))?;

    let cipher = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&*key_bytes));
    let nonce_bytes = hex::decode(&encrypted.nonce)?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = hex::decode(&encrypted.ciphertext)?;
    let plaintext = Zeroizing::new(cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| anyhow!("Decryption failed. Incorrect passphrase?"))?);

    let mut private_key_bytes = Zeroizing::new([0u8; 32]);
    private_key_bytes.copy_from_slice(&plaintext);

    let signing_key = SigningKey::from_bytes(&private_key_bytes);
    let signing_pubkey = signing_key.verifying_key().to_bytes();

    // KEYLESS DRAFT HANDLING:
    // If artifact has no author pubkey (all zeros), bind it to this key now.
    // If artifact already has a pubkey, validate it matches the signing key.
    if !artifact.has_author_pubkey() {
        println!("[OK] Binding keyless draft to key: {}\n", key_name);
        artifact.author_pubkey = signing_pubkey;
    } else {
        // CRITICAL VALIDATION: Verify artifact's public key matches signing key
        if artifact.author_pubkey != signing_pubkey {
            return Err(anyhow!(
                "Cannot sign: artifact was created with different key\n\n\
                 Artifact public key: {}\n\
                 Your signing key:    {}\n\n\
                 You cannot sign artifacts created with a different key.\n\
                 The artifact must be recreated with your current active key.",
                hex::encode(artifact.author_pubkey),
                hex::encode(signing_pubkey)
            ));
        }
    }

    // Sign the artifact
    let signing_bytes = artifact.author_signing_bytes();
    let signature = crypto::sign(&signing_key, &signing_bytes);

    let signed_artifact = Artifact {
        version: artifact.version,
        flags: artifact.flags,
        artifact_id: artifact.artifact_id,
        timestamp: artifact.timestamp,
        intent: artifact.intent,
        author_pubkey: artifact.author_pubkey,
        author_signature: signature,
        reserved_a: artifact.reserved_a,
        note_hash: artifact.note_hash,
        seal_pubkey: artifact.seal_pubkey,
        seal_signature: artifact.seal_signature,
    };

    let _signed = state::require_typed_signed(signed_artifact.clone())?;

    // Write back to disk
    let signed_bytes = signed_artifact.to_bytes();
    fs::write(&file, &signed_bytes).context("Failed to write signed artifact")?;

    let details = vec![
        ("File", file.display().to_string()),
        ("ID", signed_artifact.artifact_id.short_display()),
        ("State", "SIGNED (unsealed)".to_string()),
    ];
    
    crate::prompts::print_success_box("Artifact Signed", &details);
    
    use console::Style;
    let dim = Style::new().dim();
    println!("{}", dim.apply_to("Next steps:"));
    println!("  {} Seal it:   vwh seal {}", dim.apply_to("1."), file.display());
    println!("  {} Inspect:   vwh inspect {}", dim.apply_to("2."), file.display());
    println!();

    Ok(())
}

/// Seal a signed artifact
pub fn seal(file: PathBuf, key_name_opt: Option<String>) -> Result<()> {
    // Load artifact
    let bytes = fs::read(&file).context("Failed to read artifact file")?;
    let artifact = Artifact::from_bytes(&bytes).context("Failed to parse artifact")?;

    // Validate state: must be signed, must not be sealed
    state::require_signed_unsealed(&artifact)?;
    let _signed = state::require_typed_signed(artifact.clone())?;

    match artifact.version {
        ArtifactVersion::V1 => {
            // V1: Simple flag toggle (no key needed)
            let sealed_artifact = artifact.with_seal_flag();
            let _sealed = state::require_typed_sealed(sealed_artifact.clone())?;

            // Write back
            fs::write(&file, sealed_artifact.to_bytes())?;
            
            // Update ledger
            let config_dir = get_config_dir()?;
            let registry_mgr = RegistryManager::new(config_dir);
            let mut ledger = registry_mgr.load_ledger()?;
            ledger.add_or_update_artifact(LedgerEntry {
                id: sealed_artifact.artifact_id.to_hex(),
                fingerprint: sealed_artifact.author_fingerprint().to_hex(),
                created_at: Some(sealed_artifact.timestamp.to_rfc3339()),
                status: "active".to_string(),
                revoked_at: None,
                reason: None,
            });
            registry_mgr.save_ledger(&ledger)?;

            println!("\n[V1] Artifact SEALED (flag set)\n");
            println!("  ID:    {}", sealed_artifact.artifact_id);
            println!("  State: SEALED (immutable)\n");
        }
        ArtifactVersion::V2 => {
            // V2: Dual signature - requires sealing key
            
            // Find sealing key name
            let key_name: String = if let Some(name) = key_name_opt {
                // User specified - resolve label/name then verify it's a sealing key
                let resolved = crate::key::resolve_key_name(&name)?;
                let key_type = get_key_type(&resolved)?;
                if key_type != KeyType::Sealing {
                    bail!(
                        "Cannot seal with {} key '{}'\n\n\
                         Sealing requires a sealing key.\n\
                         Signing keys can only be used for the sign command.\n\n\
                         Create a sealing key with: vwh key init --type sealing",
                        key_type, resolved
                    );
                }
                use console::Style;
                let cyan = Style::new().cyan();
                println!("{}", cyan.apply_to(format!("Using specified sealing key: {}", resolved)));
                println!();
                resolved
            } else {
                // Interactive sealing key selection
                let config_dir = get_config_dir()?;
                let registry_mgr = RegistryManager::new(config_dir.clone());
                let registry = registry_mgr.load_keys_v2()?;
                let sealing_keys: Vec<KeyEntryV2> = registry.get_sealing_keys().into_iter().cloned().collect();

                crate::prompts::select_key(&sealing_keys, "sealing")?
            };
            
            // Load sealing key
            let key_file = crate::key::key_path_for(&key_name)?;
            let passphrase = read_passphrase("Enter sealing key passphrase: ")?;
            
            // Decrypt private key
            let json = fs::read_to_string(&key_file)?;
            let encrypted: EncryptedKeyFile = serde_json::from_str(&json)?;

            let argon2 = build_argon2()?;

            let salt_raw = decode_salt_for_kdf(encrypted.version, &encrypted.salt)?;
            let mut key_bytes = Zeroizing::new([0u8; 32]);
            argon2.hash_password_into(passphrase.as_bytes(), &salt_raw, &mut *key_bytes)
                .map_err(|e| anyhow!("Key derivation failed: {}", e))?;

            let cipher = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&*key_bytes));
            let nonce_bytes = hex::decode(&encrypted.nonce)?;
            let nonce = Nonce::from_slice(&nonce_bytes);

            let ciphertext = hex::decode(&encrypted.ciphertext)?;
            let plaintext = Zeroizing::new(cipher
                .decrypt(nonce, ciphertext.as_ref())
                .map_err(|_| anyhow!("Decryption failed. Incorrect passphrase?"))?);

            let mut private_key_bytes = Zeroizing::new([0u8; 32]);
            private_key_bytes.copy_from_slice(&plaintext);

            let signing_key = SigningKey::from_bytes(&private_key_bytes);
            let seal_pubkey = signing_key.verifying_key().to_bytes();

            // seal_signing_bytes() includes seal_pubkey — set it in the artifact
            // before signing so the signature covers the real pubkey, not zeroes
            let artifact = artifact.with_seal(seal_pubkey, [0u8; 64]);
            let seal_bytes = artifact.seal_signing_bytes()?;
            let seal_signature = crypto::sign(&signing_key, &seal_bytes);

            // Add seal
            let sealed_artifact = artifact.with_seal(seal_pubkey, seal_signature);
            
            // Write back
            fs::write(&file, sealed_artifact.to_bytes())?;
            
            // Update ledger
            let config_dir = get_config_dir()?;
            let registry_mgr = RegistryManager::new(config_dir);
            let mut ledger = registry_mgr.load_ledger()?;
            ledger.add_or_update_artifact(LedgerEntry {
                id: sealed_artifact.artifact_id.to_hex(),
                fingerprint: sealed_artifact.author_fingerprint().to_hex(),
                created_at: Some(sealed_artifact.timestamp.to_rfc3339()),
                status: "active".to_string(),
                revoked_at: None,
                reason: None,
            });
            registry_mgr.save_ledger(&ledger)?;

            let details = vec![
                ("File", file.display().to_string()),
                ("ID", sealed_artifact.artifact_id.short_display()),
                ("Author key", hex::encode(&sealed_artifact.author_pubkey[..8])),
                ("Seal key", hex::encode(&seal_pubkey[..8])),
                ("State", "SEALED (immutable)".to_string()),
            ];
            
            crate::prompts::print_success_box("Artifact Sealed (Dual-Signed)", &details);
        }
    }

    use console::Style;
    let yellow = Style::new().yellow().bold();
    let dim = Style::new().dim();
    
    println!("{}", yellow.apply_to("⚠ This artifact is now immutable and cannot be:"));
    println!("  {} Edited", dim.apply_to("•"));
    println!("  {} Unsigned", dim.apply_to("•"));
    println!("  {} Modified in any way", dim.apply_to("•"));
    println!();
    println!("{}", dim.apply_to(format!("Verify: vwh inspect {}", file.display())));
    println!();

    Ok(())
}

/// Unseal a sealed artifact (V2 only - removes seal signature)
pub fn unseal(file: PathBuf) -> Result<()> {
    // Load artifact
    let bytes = fs::read(&file).context("Failed to read artifact file")?;
    let artifact = Artifact::from_bytes(&bytes).context("Failed to parse artifact")?;

    // V2 only
    if artifact.version != ArtifactVersion::V2 {
        bail!(
            "unseal only works with v2 artifacts.\n\n\
             V1 artifacts use a seal flag that cannot be safely removed.\n\
             To unsign a v1 artifact, use: vwh unsign"
        );
    }

    // Must be sealed — enforced at both runtime and type level
    let _sealed = state::require_typed_sealed(artifact.clone())?;

    // Check if artifact is revoked in ledger
    let config_dir = get_config_dir()?;
    let registry_mgr = RegistryManager::new(config_dir);
    let ledger = registry_mgr.load_ledger()?;

    let artifact_id_hex = artifact.artifact_id.to_hex();
    if let Some(entry) = ledger.get_artifact(&artifact_id_hex) {
        if entry.status == "revoked" {
            return Err(anyhow!(
                "Cannot unseal: artifact is revoked in ledger.\n\
                 Unsealing a revoked artifact would create confusion about its status."
            ));
        }
    }

    // Remove seal
    let unsealed_artifact = artifact.without_seal_signature();

    // Write back
    fs::write(&file, unsealed_artifact.to_bytes())?;

    let details = vec![
        ("File", file.display().to_string()),
        ("State", "Author-signed (unsealed)".to_string()),
    ];
    
    crate::prompts::print_success_box("Seal Removed", &details);
    
    use console::Style;
    let dim = Style::new().dim();
    println!("{}", dim.apply_to("The artifact can now be re-sealed:"));
    println!("  {} vwh seal {} --key <sealing-key>", dim.apply_to("→"), file.display());
    println!();

    Ok(())
}

/// Unsign a signed but unsealed artifact
pub fn unsign(file: PathBuf) -> Result<()> {
    // Load artifact
    let bytes = fs::read(&file).context("Failed to read artifact file")?;
    let artifact = Artifact::from_bytes(&bytes).context("Failed to parse artifact")?;

    // Validate state: must be signed, must not be sealed — enforced at both runtime and type level
    state::require_signed_unsealed(&artifact)?;
    let _signed = state::require_typed_signed(artifact.clone())?;

    // Check if artifact is revoked in ledger
    let config_dir = get_config_dir()?;
    let registry_mgr = RegistryManager::new(config_dir);
    let ledger = registry_mgr.load_ledger()?;

    let artifact_id_hex = artifact.artifact_id.to_hex();
    if let Some(entry) = ledger.get_artifact(&artifact_id_hex) {
        if entry.status == "revoked" {
            return Err(anyhow!(
                "Cannot unsign: artifact is revoked in ledger.\n\
                 Unsigning a revoked artifact would create confusion about its status."
            ));
        }
    }

    // Remove signature AND pubkey - return to keyless draft state
    // This allows signing with a different key later
    let unsigned_artifact = Artifact {
        version: artifact.version,
        flags: artifact.flags,
        artifact_id: artifact.artifact_id,
        timestamp: artifact.timestamp,
        intent: artifact.intent,
        author_pubkey: vwh_core::format::ZERO_PUBKEY,
        author_signature: [0u8; 64],
        reserved_a: artifact.reserved_a,
        note_hash: artifact.note_hash,
        seal_pubkey: [0u8; 32],
        seal_signature: [0u8; 64],
    };

    // Write back to disk
    let unsigned_bytes = unsigned_artifact.to_bytes();
    fs::write(&file, &unsigned_bytes).context("Failed to write unsigned artifact")?;

    println!("\n[OK] Artifact unsigned successfully\n");
    println!("  ID:    {}", unsigned_artifact.artifact_id);
    println!("  State: KEYLESS DRAFT\n");
    println!("You can now:");
    println!("  - Sign with any key: vwh sign {}", file.display());
    println!("  - Sign with specific key: vwh sign {} --key <name>\n", file.display());

    Ok(())
}

/// Edit draft artifact metadata
pub fn edit(
    file: PathBuf,
    new_intent: Option<String>,
    new_note: Option<String>,
) -> Result<()> {
    // Load artifact
    let bytes = fs::read(&file).context("Failed to read artifact file")?;
    let mut artifact = Artifact::from_bytes(&bytes).context("Failed to parse artifact")?;

    // Validate state
    state::require_draft(&artifact)?;

    // Apply changes
    let mut changed = false;

    if let Some(intent_str) = new_intent {
        let new_intent_val = Intent::from_str(&intent_str).context("Invalid intent")?;
        artifact.intent = new_intent_val;
        changed = true;
        println!("[OK] Intent updated to: {}", artifact.intent);
    }

    if new_note.is_some() {
        // Note is not stored in artifact binary format currently
        // This is a limitation - we'd need to extend the format to support this
        println!("[WARN] Note editing not yet implemented (format limitation)");
    }

    if !changed {
        println!("No changes specified. Use --intent or --note flags.");
        return Ok(());
    }

    // Write back to disk
    let edited_bytes = artifact.to_bytes();
    fs::write(&file, &edited_bytes).context("Failed to write edited artifact")?;

    println!("\n[OK] Artifact edited successfully\n");
    println!("  ID:    {}", artifact.artifact_id);
    println!("  State: UNSIGNED DRAFT\n");

    Ok(())
}

/// Key rotation: create new key, mark old as deprecated
pub fn key_rotate() -> Result<()> {
    let config_dir = get_config_dir()?;
    let registry_mgr = RegistryManager::new(config_dir.clone());

    println!("\n== Key Rotation ==\n");

    // Prompt user to select which active key to rotate
    let all_active: Vec<KeyEntryV2> = registry_mgr.load_keys_v2()?.get_active_keys().into_iter().cloned().collect();
    let current_key_name = crate::prompts::select_key_for_rotation(&all_active)?;

    let key_file = crate::key::key_path_for(&current_key_name)?;
    if !key_file.exists() {
        return Err(anyhow!("Key file not found for selected key"));
    }

    // Find label for display
    let current_label = all_active.iter()
        .find(|k| {
            crate::key::resolve_key_name(&k.label)
                .map(|n| n == current_key_name)
                .unwrap_or(false)
        })
        .map(|k| k.label.as_str())
        .unwrap_or(&current_key_name)
        .to_string();

    println!("\nRotating: {}\n", current_label);

    let passphrase = read_passphrase("Enter CURRENT passphrase: ")?;

    // Load and decrypt current key to get fingerprint
    let json = fs::read_to_string(&key_file)?;
    let encrypted: EncryptedKeyFile = serde_json::from_str(&json)?;

    let argon2 = build_argon2()?;

    let salt_raw = decode_salt_for_kdf(encrypted.version, &encrypted.salt)?;
    let mut key_bytes = Zeroizing::new([0u8; 32]);
    argon2.hash_password_into(passphrase.as_bytes(), &salt_raw, &mut *key_bytes)
        .map_err(|e| anyhow!("Key derivation failed: {}", e))?;

    let cipher = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&*key_bytes));
    let nonce_bytes = hex::decode(&encrypted.nonce)?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = hex::decode(&encrypted.ciphertext)?;
    let plaintext = Zeroizing::new(cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| anyhow!("Decryption failed. Incorrect passphrase?"))?);

    let mut private_key_bytes = Zeroizing::new([0u8; 32]);
    private_key_bytes.copy_from_slice(&plaintext);

    let old_signing_key = SigningKey::from_bytes(&private_key_bytes);
    let old_public_key = old_signing_key.verifying_key().to_bytes();
    let old_fingerprint = vwh_core::KeyFingerprint::new(&old_public_key);

    // Load registry for key type lookup (before any mutation)
    let mut keys_registry = registry_mgr.load_keys_v2()?;

    // Determine key type of old key for label prompt
    let old_key_type = keys_registry.keys.iter()
        .find(|k| k.fingerprint == old_fingerprint.to_hex())
        .map(|k| k.key_type.as_str())
        .unwrap_or("signing")
        .to_string();

    // Generate new key name, prompt for label, then get new passphrase
    let new_key_name = crate::key::generate_key_name();
    let new_label = crate::prompts::prompt_key_label(&old_key_type)?;
    println!("\nGenerating new key: {}\n", new_key_name);

    let new_passphrase = read_passphrase("Enter NEW passphrase: ")?;
    let new_passphrase_confirm = read_passphrase("Confirm NEW passphrase: ")?;

    if *new_passphrase != *new_passphrase_confirm {
        return Err(anyhow!("Passphrases do not match"));
    }

    if new_passphrase.len() < 8 {
        return Err(anyhow!("Passphrase must be at least 8 characters"));
    }

    // Generate new Ed25519 keypair
    let mut new_seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *new_seed).context("OS entropy unavailable")?;
    let new_signing_key = SigningKey::from_bytes(&new_seed);
    let new_public_key = new_signing_key.verifying_key().to_bytes();
    let new_private_key = new_signing_key.to_bytes();
    let new_fingerprint = vwh_core::KeyFingerprint::new(&new_public_key);

    // Encrypt new private key
    let mut salt_bytes_new = [0u8; 16];
    getrandom::fill(&mut salt_bytes_new).context("OS entropy unavailable")?;
    let salt_hex_new = hex::encode(salt_bytes_new);

    let argon2_new = build_argon2()?;

    let mut new_key_bytes = Zeroizing::new([0u8; 32]);
    argon2_new
        .hash_password_into(new_passphrase.as_bytes(), &salt_bytes_new, &mut *new_key_bytes)
        .map_err(|e| anyhow!("Key derivation failed: {}", e))?;

    let cipher_new = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&*new_key_bytes));
    let mut nonce_bytes_new = [0u8; 12];
    getrandom::fill(&mut nonce_bytes_new).context("OS entropy unavailable")?;
    let nonce_new = Nonce::from_slice(&nonce_bytes_new);

    let ciphertext_new = cipher_new
        .encrypt(nonce_new, new_private_key.as_ref())
        .map_err(|e| anyhow!("Encryption failed: {}", e))?;

    // Prepare encrypted key file
    let encrypted_new = EncryptedKeyFile {
        salt: salt_hex_new,
        nonce: hex::encode(nonce_bytes_new),
        ciphertext: hex::encode(&ciphertext_new),
        version: 2,
        created_at: Utc::now().to_rfc3339(),
    };

    // Write new key to disk FIRST (before deprecating old key)
    // If write fails, old key remains active — no data loss
    let new_key_dir = crate::key::get_key_dir(&new_key_name)?;
    fs::create_dir_all(&new_key_dir)?;

    let new_key_file = crate::key::key_path_for(&new_key_name)?;
    let new_pubkey_file = new_key_dir.join("identity.pub");

    let json_new = serde_json::to_string_pretty(&encrypted_new)?;
    fs::write(&new_key_file, json_new)?;
    fs::write(&new_pubkey_file, hex::encode(new_public_key))?;

    // Only now mark old key as deprecated — new key is safely on disk
    keys_registry.mark_deprecated(&old_fingerprint.to_hex())?;

    // Add new key to registry as active
    keys_registry.add_key(KeyEntryV2 {
        fingerprint: new_fingerprint.to_hex(),
        public_key: hex::encode(new_public_key),
        created_at: Utc::now().to_rfc3339(),
        key_type: old_key_type,
        status: "active".to_string(),
        label: new_label,
        deprecated_at: None,
        revoked_at: None,
        is_demo: None,
    });

    // Save updated registry
    registry_mgr.save_keys_v2(&keys_registry)?;

    println!("\n[OK] Key rotated successfully\n");
    println!("Old key (deprecated): {}", old_fingerprint.short_display());
    println!("                      {}", current_key_name);
    println!("New key (active):     {}", new_fingerprint.short_display());
    println!("                      {}\n", new_key_name);
    println!("The old key remains valid for verifying existing artifacts.");
    println!("Run 'vwh dump keys' to see updated registry.\n");

    Ok(())
}

/// Revoke a key
pub fn key_revoke(reason: String, _note: Option<String>) -> Result<()> {
    let config_dir = get_config_dir()?;
    let registry_mgr = RegistryManager::new(config_dir);

    // Prompt user to select which active key to revoke
    let all_active: Vec<KeyEntryV2> = registry_mgr.load_keys_v2()?.get_active_keys().into_iter().cloned().collect();
    let key_name = crate::prompts::select_key_for_rotation(&all_active)?;

    let key_file = crate::key::key_path_for(&key_name)?;
    if !key_file.exists() {
        return Err(anyhow!("Key file not found for selected key"));
    }

    let passphrase = read_passphrase("Enter passphrase: ")?;

    // Decrypt to get fingerprint
    let json = fs::read_to_string(&key_file)?;
    let encrypted: EncryptedKeyFile = serde_json::from_str(&json)?;

    let argon2 = build_argon2()?;

    let salt_raw = decode_salt_for_kdf(encrypted.version, &encrypted.salt)?;
    let mut key_bytes = Zeroizing::new([0u8; 32]);
    argon2.hash_password_into(passphrase.as_bytes(), &salt_raw, &mut *key_bytes)
        .map_err(|e| anyhow!("Key derivation failed: {}", e))?;

    let cipher = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&*key_bytes));
    let nonce_bytes = hex::decode(&encrypted.nonce)?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = hex::decode(&encrypted.ciphertext)?;
    let plaintext = Zeroizing::new(cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| anyhow!("Decryption failed. Incorrect passphrase?"))?);

    let mut private_key_bytes = Zeroizing::new([0u8; 32]);
    private_key_bytes.copy_from_slice(&plaintext);

    let signing_key = SigningKey::from_bytes(&private_key_bytes);
    let public_key = signing_key.verifying_key().to_bytes();
    let fingerprint = vwh_core::KeyFingerprint::new(&public_key);

    println!("\n[WARN] KEY REVOCATION\n");
    println!("Key name:        {}", key_name);
    println!("Key fingerprint: {}", fingerprint.to_hex());
    println!("Reason: {}\n", reason);

    println!("This will:");
    println!("  - Mark the key as REVOKED in keys.json");
    println!("  - Affect all artifacts signed with this key\n");

    println!("Type 'REVOKE' to confirm: ");
    let mut confirmation = String::new();
    std::io::stdin().read_line(&mut confirmation)?;

    if confirmation.trim() != "REVOKE" {
        println!("Revocation cancelled.");
        return Ok(());
    }

    // Update keys registry
    let mut keys_registry = registry_mgr.load_keys_v2()?;
    keys_registry.mark_revoked(&fingerprint.to_hex())?;
    registry_mgr.save_keys_v2(&keys_registry)?;

    println!("\n[OK] Key revoked successfully\n");
    println!("Run 'vwh dump keys' to see changes.\n");

    Ok(())
}

/// Revoke an artifact
pub fn artifact_revoke(
    artifact_id_str: String,
    reason: String,
    _note: Option<String>,
) -> Result<()> {
    let config_dir = get_config_dir()?;
    let registry_mgr = RegistryManager::new(config_dir);

    // Parse artifact ID
    let artifact_id = vwh_core::ArtifactId::from_hex(&artifact_id_str)
        .context("Invalid artifact ID (must be 32-char hex)")?;

    // Get active key
    let key_name = crate::key::get_active_key_name()?
        .ok_or_else(|| anyhow!("No active key found. Run 'vwh key init' first."))?;
    
    let key_file = crate::key::key_path_for(&key_name)?;
    if !key_file.exists() {
        return Err(anyhow!("Active key file not found"));
    }

    let passphrase = read_passphrase("Enter passphrase: ")?;

    let json = fs::read_to_string(&key_file)?;
    let encrypted: EncryptedKeyFile = serde_json::from_str(&json)?;

    let argon2 = build_argon2()?;

    let salt_raw = decode_salt_for_kdf(encrypted.version, &encrypted.salt)?;
    let mut key_bytes = Zeroizing::new([0u8; 32]);
    argon2.hash_password_into(passphrase.as_bytes(), &salt_raw, &mut *key_bytes)
        .map_err(|e| anyhow!("Key derivation failed: {}", e))?;

    let cipher = ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(&*key_bytes));
    let nonce_bytes = hex::decode(&encrypted.nonce)?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = hex::decode(&encrypted.ciphertext)?;
    let plaintext = Zeroizing::new(cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| anyhow!("Decryption failed. Incorrect passphrase?"))?);

    let mut private_key_bytes = Zeroizing::new([0u8; 32]);
    private_key_bytes.copy_from_slice(&plaintext);

    let signing_key = SigningKey::from_bytes(&private_key_bytes);
    let public_key = signing_key.verifying_key().to_bytes();
    let fingerprint = vwh_core::KeyFingerprint::new(&public_key);

    // ARCH-4: Ownership check — only the author key can revoke the artifact
    let mut ledger = registry_mgr.load_ledger()?;
    let artifact_id_hex = artifact_id.to_hex();
    if let Some(entry) = ledger.get_artifact(&artifact_id_hex) {
        if entry.fingerprint != fingerprint.to_hex() {
            return Err(anyhow!(
                "Cannot revoke: artifact was not created by this key.\n\n\
                 Artifact author fingerprint: {}\n\
                 Your key fingerprint:        {}",
                entry.fingerprint,
                fingerprint.to_hex()
            ));
        }
    }

    println!("\n[WARN] ARTIFACT REVOCATION\n");
    println!("Artifact ID: {}", artifact_id);
    println!("Reason: {}\n", reason);
    let existing_created_at = ledger.get_artifact(&artifact_id.to_hex())
        .and_then(|e| e.created_at.clone());
    ledger.add_or_update_artifact(LedgerEntry {
        id: artifact_id.to_hex(),
        fingerprint: fingerprint.to_hex(),
        created_at: existing_created_at,
        status: "revoked".to_string(),
        revoked_at: Some(Utc::now().to_rfc3339()),
        reason: Some(reason),
    });
    registry_mgr.save_ledger(&ledger)?;

    println!("[OK] Artifact revoked successfully\n");
    println!("Run 'vwh dump ledger' to see changes.\n");

    Ok(())
}

/// Dump registry data as JSON
pub fn dump(target: crate::DumpTarget) -> Result<()> {
    let config_dir = get_config_dir()?;
    let registry_mgr = RegistryManager::new(config_dir);

    match target {
        crate::DumpTarget::Keys => {
            let keys = registry_mgr.load_keys_v2()?;
            let json = serde_json::to_string_pretty(&keys)?;
            println!("{}", json);
        }
        crate::DumpTarget::Ledger => {
            let ledger = registry_mgr.load_ledger()?;
            let json = serde_json::to_string_pretty(&ledger)?;
            println!("{}", json);
        }
    }

    Ok(())
}

const REGISTRY_REMOTE: &str = "git@github.com:notvcto/vwh-registry.git";

pub fn push_registry() -> Result<()> {
    let config_dir = get_config_dir()?;
    let registry_dir = config_dir.join("registry");

    let run_git = |args: &[&str]| -> Result<()> {
        let out = std::process::Command::new("git")
            .arg("-C").arg(&registry_dir)
            .args(args)
            .output()
            .context("Failed to run git")?;
        if !out.status.success() {
            anyhow::bail!(
                "git {}: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(())
    };

    // Clone if not present, pull if it is
    if !registry_dir.join(".git").exists() {
        println!("Cloning registry...");
        let out = std::process::Command::new("git")
            .args(["clone", REGISTRY_REMOTE])
            .arg(&registry_dir)
            .output()
            .context("Failed to run git clone")?;
        if !out.status.success() {
            anyhow::bail!(
                "git clone failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        println!("Cloned.");
    } else {
        println!("Pulling latest...");
        run_git(&["pull", "--rebase"])?;
        println!("Up to date.");
    }

    let version_dir = registry_dir.join("v2");
    if !version_dir.exists() {
        std::fs::create_dir_all(&version_dir).context("Failed to create v2/ directory")?;
    }

    std::fs::copy(config_dir.join("keys.json"), version_dir.join("keys.json"))
        .context("Failed to copy keys.json")?;
    std::fs::copy(config_dir.join("ledger.json"), version_dir.join("ledger.json"))
        .context("Failed to copy ledger.json")?;

    let registry_mgr = RegistryManager::new(config_dir);
    let keys = registry_mgr.load_keys_v2()?;
    let ledger = registry_mgr.load_ledger()?;
    let n_keys = keys.keys.len();
    let n_artifacts = ledger.artifacts.len();

    run_git(&["add", "v2/keys.json", "v2/ledger.json"])?;

    let staged = std::process::Command::new("git")
        .arg("-C").arg(&registry_dir)
        .args(["diff", "--cached", "--quiet"])
        .status()
        .context("Failed to run git diff")?;

    if staged.success() {
        println!("Nothing to push — registry is already up to date.");
        return Ok(());
    }

    let commit_msg = format!(
        "Update registry v2: {} keys, {} artifacts\n\n[vwh push]",
        n_keys, n_artifacts
    );
    run_git(&["commit", "-S", "-m", &commit_msg])?;
    // Pull --rebase before push to handle concurrent remote commits
    run_git(&["pull", "--rebase", "origin", "main"])?;
    run_git(&["push"])?;

    println!("Registry pushed and signed.");
    println!("  Keys:      {}", n_keys);
    println!("  Artifacts: {}", n_artifacts);
    Ok(())
}

