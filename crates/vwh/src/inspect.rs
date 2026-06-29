//! Public inspector: `inspect` and `note` commands.
//!
//! Exit codes:
//!   0 = artifact verified (all signatures valid, key not revoked)
//!   1 = fatal error (I/O, argument parsing, internal error)
//!   2 = cryptographic failure (invalid signature, revoked key, tampered content)
//!   3 = registry unavailable (could not fetch registry, but crypto passed)
//!
//! NOTE: this module carries its own deserialize-only registry structs
//! (`KeysRegistry`/`LedgerRegistry`), distinct from the read-write
//! `registry::*` types used by the author commands. Deduplicating the two
//! is deferred tech debt — do not merge them without a deliberate pass.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;
use vwh_core::{format::Artifact, verify::verify_artifact};

pub(crate) const DEFAULT_REGISTRY_URL: &str = "https://notvc.to/vwh-registry";
const SECTION_SEP: &str = "-----------------------------------------";
const GITHUB_API_BASE: &str = "https://api.github.com";

// The backing GitHub repo is no longer hardcoded — it is discovered from each
// registry's own index.html descriptor (see `discover_registry_repo`). This is
// what lets notvc.to and any community registry use the exact same trust path.

fn print_sep() {
    println!("{}\n", SECTION_SEP);
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
    #[serde(default)]
    is_demo: bool,
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
    #[serde(default)]
    #[allow(dead_code)]
    created_at: Option<String>,
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

#[derive(Deserialize)]
struct GithubCommit {
    sha: String,
    commit: GithubCommitInner,
}

#[derive(Deserialize)]
struct GithubCommitInner {
    verification: GithubVerification,
}

#[derive(Deserialize)]
struct GithubVerification {
    verified: bool,
    reason: String,
}

enum CommitCheck {
    Signed { sha: String },
    Unsigned { reason: String, sha: String, fallback_sha: Option<String> },
    Unavailable(String),
}

fn fetch_registry(base_url: &str, offline: bool, artifact_version: u16, client: &reqwest::blocking::Client) -> RegistryStatus {
    if offline {
        return RegistryStatus::Unavailable("Offline mode".to_string());
    }

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

/// Discover the GitHub repo (`owner/repo`) backing a registry by reading the
/// `vwh-registry-repo` descriptor from its `index.html`. Returns `None` if the
/// page is unreachable, has no descriptor, or names an implausible repo — in
/// which case the caller treats the registry as advisory (TLS only).
fn discover_registry_repo(base_url: &str, client: &reqwest::blocking::Client) -> Option<String> {
    let url = format!("{}/index.html", base_url.trim_end_matches('/'));
    let resp = client.get(&url).send().ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let html = resp.text().ok()?;
    extract_meta(&html, "vwh-registry-repo").filter(|r| is_valid_repo(r))
}

/// Pull the `content="..."` of the `<meta name="<name>" ...>` tag, tolerant of
/// attribute order. No HTML parser — a registry descriptor is a fixed shape.
fn extract_meta(html: &str, name: &str) -> Option<String> {
    let needle = format!("name=\"{}\"", name);
    let at = html.find(&needle)?;
    let tag_start = html[..at].rfind('<')?;
    let tag_end = at + html[at..].find('>')?;
    let tag = &html[tag_start..tag_end];
    let cval = tag.split_once("content=\"")?.1;
    let end = cval.find('"')?;
    Some(cval[..end].trim().to_string())
}

/// Accept only a plausible `owner/repo` before it ever reaches a GitHub API URL.
fn is_valid_repo(s: &str) -> bool {
    let ok = |seg: &str| {
        !seg.is_empty()
            && seg.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    };
    let mut parts = s.split('/');
    matches!((parts.next(), parts.next(), parts.next()), (Some(o), Some(r), None) if ok(o) && ok(r))
}

fn check_commit_signature(repo: &str, client: &reqwest::blocking::Client) -> CommitCheck {
    let url = format!("{}/repos/{}/commits/HEAD", GITHUB_API_BASE, repo);
    let head: GithubCommit = match client.get(&url).send() {
        Ok(r) if r.status().is_success() => match r.json() {
            Ok(c) => c,
            Err(e) => return CommitCheck::Unavailable(format!("GitHub API parse error: {}", e)),
        },
        Ok(r) => return CommitCheck::Unavailable(format!("GitHub API HTTP {}", r.status())),
        Err(e) => return CommitCheck::Unavailable(format!("GitHub API unreachable: {}", e)),
    };

    if head.commit.verification.verified {
        return CommitCheck::Signed { sha: head.sha };
    }

    let list_url = format!("{}/repos/{}/commits?per_page=20", GITHUB_API_BASE, repo);
    let commits: Vec<GithubCommit> = client
        .get(&list_url)
        .send()
        .map_err(|e| { eprintln!("[WARN] commit history: {}", e); e })
        .ok()
        .and_then(|r| r.json().ok())
        .unwrap_or_default();

    let fallback_sha = commits.iter()
        .find(|c| c.commit.verification.verified)
        .map(|c| c.sha.clone());

    CommitCheck::Unsigned {
        reason: head.commit.verification.reason,
        sha: head.sha,
        fallback_sha,
    }
}

fn fetch_at_commit(repo: &str, sha: &str, artifact_version: u16, client: &reqwest::blocking::Client) -> Option<(KeysRegistry, LedgerRegistry)> {
    let base = format!(
        "{}/repos/{}/contents/v{}",
        GITHUB_API_BASE, repo, artifact_version
    );

    let keys_bytes = client
        .get(format!("{}/keys.json?ref={}", base, sha))
        .header("Accept", "application/vnd.github.raw")
        .send()
        .map_err(|e| { eprintln!("[WARN] fetch_at_commit: failed to fetch keys.json: {}", e); e })
        .ok()?
        .bytes()
        .map_err(|e| { eprintln!("[WARN] fetch_at_commit: failed to read keys.json bytes: {}", e); e })
        .ok()?;

    let ledger_bytes = client
        .get(format!("{}/ledger.json?ref={}", base, sha))
        .header("Accept", "application/vnd.github.raw")
        .send()
        .map_err(|e| { eprintln!("[WARN] fetch_at_commit: failed to fetch ledger.json: {}", e); e })
        .ok()?
        .bytes()
        .map_err(|e| { eprintln!("[WARN] fetch_at_commit: failed to read ledger.json bytes: {}", e); e })
        .ok()?;

    let keys = serde_json::from_slice::<KeysRegistry>(&keys_bytes)
        .map_err(|e| { eprintln!("[WARN] fetch_at_commit: failed to parse keys.json: {}", e); e })
        .ok()?;
    let ledger = serde_json::from_slice::<LedgerRegistry>(&ledger_bytes)
        .map_err(|e| { eprintln!("[WARN] fetch_at_commit: failed to parse ledger.json: {}", e); e })
        .ok()?;

    Some((keys, ledger))
}

pub fn inspect(file: PathBuf, offline: bool, registry_url: Option<String>) -> Result<()> {
    println!("\n== VWH Artifact Inspector ==\n");

    // Single shared HTTP client for all network operations (M8 + M9)
    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(10))
        .user_agent("vwh-inspector/2.0")
        .build()?;

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

    // Registry declared by the artifact's own note (verified below). Lets each
    // artifact point at its own registry instead of a single hardcoded one.
    let mut note_registry: Option<String> = None;

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
                            // Hash verified — trust the note's registry header.
                            let (headers, _) = crate::note_meta::parse_note(&note_content);
                            note_registry = headers.get("registry").cloned();
                            println!("  [OK] Note file found: {}", note_path.display());
                            println!("  [OK] Note hash verified (BLAKE3)");
                            println!("  [OK] Note integrity confirmed");
                            if let Some(ref r) = note_registry {
                                println!("  [INFO] Note declares registry: {}", r);
                            }
                            println!("  [INFO] Run 'vwh note {}' to view note content.\n", file.display());
                        } else {
                            eprintln!("  [ERR] Note file found but hash MISMATCH");
                            eprintln!("       Expected: {}", hex::encode(artifact.note_hash));
                            eprintln!("       Got:      {}", hex::encode(computed_hash.as_bytes()));
                            eprintln!("  [ERR] Note may have been tampered with");
                            std::process::exit(2);
                        }
                    }
                    Err(e) => {
                        eprintln!("  [ERR] Failed to read note file: {}", e);
                        eprintln!("  [ERR] Cannot verify note integrity");
                        std::process::exit(2);
                    }
                }
            } else {
                eprintln!("  [ERR] Note hash present but file NOT FOUND");
                eprintln!("       Expected: {}", note_path.display());
                eprintln!("  [ERR] This artifact is INVALID (missing required note)");
                std::process::exit(2);
            }
        } else {
            eprintln!("  [WARN] NO NOTE ATTACHED");
            eprintln!("         Note hash is zero (edge case)");
            eprintln!("         This should not happen in normal v2 workflow");
        }
    }

    // Verify signature
    print_sep();
    println!("Cryptographic Verification:\n");

    // Check SEAL flag consistency (V1) or dual signature (V2)
    if artifact.version == vwh_core::format::ArtifactVersion::V1
        && artifact.is_sealed()
        && !artifact.has_signature()
    {
        eprintln!("  [ERR] INVALID: Artifact is sealed but unsigned");
        eprintln!("  [ERR] This is a malformed artifact");
        std::process::exit(2);
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
                let seal_bytes = match artifact.seal_signing_bytes() {
                    Ok(b) => b,
                    Err(e) => {
                        eprintln!("  [ERR] Could not compute seal signing bytes: {}", e);
                        std::process::exit(2);
                    }
                };
                match verify(&artifact.seal_pubkey, &seal_bytes, &artifact.seal_signature) {
                    Ok(_) => {
                        println!("  [OK] Seal signature valid");
                        println!("  [OK] DUAL-SIGNED (immutable)");
                    }
                    Err(e) => {
                        eprintln!("  [ERR] Seal signature INVALID: {}", e);
                        eprintln!("  [ERR] Artifact seal may be corrupted");
                        std::process::exit(2);
                    }
                }
            } else if artifact.version == vwh_core::format::ArtifactVersion::V1 && artifact.is_sealed() {
                println!("  [OK] SEAL flag verified (artifact is immutable)");
            }

            println!();
        }
        Err(e) => {
            eprintln!("  [ERR] Author signature INVALID: {}", e);
            eprintln!("  [ERR] Artifact may be corrupted or tampered");
            std::process::exit(2);
        }
    }

    // Check for V2 seal signature via verify_seal
    if artifact.version == vwh_core::format::ArtifactVersion::V2 && artifact.is_sealed() {
        use vwh_core::verify::verify_seal;
        if let Err(e) = verify_seal(&artifact) {
            eprintln!("[ERR] Seal signature invalid: {}", e);
            std::process::exit(2);
        }
    }

    // Check registry
    print_sep();
    println!("Registry Status:\n");

    // Precedence: explicit --registry/env > the artifact's own (verified) note
    // header > built-in default.
    let base_url = registry_url
        .as_deref()
        .or(note_registry.as_deref())
        .unwrap_or(DEFAULT_REGISTRY_URL);
    let artifact_version = artifact.version.as_u16();
    let registry = fetch_registry(base_url, offline, artifact_version, &client);

    match registry {
        RegistryStatus::Available { mut keys, mut ledger } => {
            println!("  [OK] Registry available");

            // Anchor to a GPG-verified commit. The backing GitHub repo is
            // discovered from the registry's own index.html descriptor (works
            // for notvc.to and any community registry alike), and the
            // authoritative keys/ledger are read AT the verified commit — never
            // the Pages copy, which can lag behind the repo.
            match discover_registry_repo(base_url, &client) {
                Some(repo) => match check_commit_signature(&repo, &client) {
                    CommitCheck::Signed { sha } => {
                        let sha8 = sha.get(..8).unwrap_or(&sha);
                        match fetch_at_commit(&repo, &sha, artifact_version, &client) {
                            Some((k, l)) => {
                                keys = k;
                                ledger = l;
                                println!("  [OK] Backed by github.com/{} — commit signed ({})", repo, sha8);
                                println!("  [OK] Registry data read at verified commit");
                            }
                            None => {
                                eprintln!("  [WARN] Commit {} verified, but data unreadable at it — using TLS copy", sha8);
                            }
                        }
                    }
                    CommitCheck::Unsigned { reason, sha, fallback_sha } => {
                        let sha8 = sha.get(..8).unwrap_or(&sha);
                        eprintln!("  [ERR] REGISTRY HEAD UNSIGNED — possible registry forgery");
                        eprintln!("        github.com/{} HEAD {} not GPG-signed ({})", repo, sha8, reason);
                        match fallback_sha {
                            Some(fb) => {
                                let fb8 = fb.get(..8).unwrap_or(&fb).to_string();
                                match fetch_at_commit(&repo, &fb, artifact_version, &client) {
                                    Some((k, l)) => {
                                        keys = k;
                                        ledger = l;
                                        eprintln!("  [WARN] Using last signed commit: {}", fb8);
                                    }
                                    None => eprintln!("  [ERR] Could not read last signed commit — registry UNVERIFIED"),
                                }
                            }
                            None => eprintln!("  [ERR] No signed commit in last 20 — registry UNVERIFIED"),
                        }
                    }
                    CommitCheck::Unavailable(reason) => {
                        eprintln!("  [WARN] Could not verify commit signature: {} — advisory (TLS only)", reason);
                    }
                },
                None => {
                    eprintln!("  [WARN] Registry declares no backing repo — advisory (TLS only)");
                }
            }

            println!("  [OK] Last updated: {}\n", ledger.updated_at);

            // ARCH-4: Check if signing key is revoked
            if artifact.has_author_pubkey() {
                let author_fp_hex = artifact.author_fingerprint().to_hex();
                let key_entry = keys.keys.iter().find(|k| k.fingerprint == author_fp_hex);

                match key_entry {
                    Some(key) => {
                        if key.status == "revoked" {
                            eprintln!("[REVOKED] The signing key for this artifact has been revoked.");
                            std::process::exit(2);
                        }
                    }
                    None => {
                        eprintln!("[WARN] Author key not found in registry");
                    }
                }
            }

            // Check key status (full display)
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
                                        eprintln!("  [WARN] Signing key DEPRECATED");
                                        eprintln!("     Rotation timestamp unavailable — cannot time-gate");
                                    }
                                    Some(dep_at) => {
                                        match chrono::DateTime::parse_from_rfc3339(dep_at) {
                                            Ok(dep_ts) => {
                                                if artifact.timestamp < dep_ts {
                                                    println!("  [OK] Signing key deprecated after signing — artifact valid");
                                                    println!("     Deprecated: {}\n", dep_at);
                                                } else {
                                                    eprintln!("  [ERR] Artifact signed AFTER key was deprecated — INVALID");
                                                    eprintln!("     Deprecated: {}", dep_at);
                                                    std::process::exit(2);
                                                }
                                            }
                                            Err(_) => {
                                                eprintln!("  [WARN] Signing key DEPRECATED");
                                                eprintln!("     Could not parse deprecation timestamp");
                                            }
                                        }
                                    }
                                }
                            }
                            "revoked" => {
                                // already handled in ARCH-4 block above; this path won't be reached
                                // but handle defensively for the time-gated case
                                match &key.revoked_at {
                                    None => {
                                        eprintln!("  [WARN] Signing key REVOKED");
                                        eprintln!("     Revocation timestamp unavailable — treat with caution");
                                    }
                                    Some(rev_at) => {
                                        match chrono::DateTime::parse_from_rfc3339(rev_at) {
                                            Ok(rev_ts) => {
                                                if artifact.timestamp < rev_ts {
                                                    eprintln!("  [WARN] Signing key later revoked — artifact predates revocation");
                                                    eprintln!("     Revoked: {}", rev_at);
                                                } else {
                                                    eprintln!("  [ERR] Artifact signed AFTER key was revoked — INVALID");
                                                    eprintln!("     Revoked: {}", rev_at);
                                                    std::process::exit(2);
                                                }
                                            }
                                            Err(_) => {
                                                eprintln!("  [WARN] Signing key REVOKED");
                                                eprintln!("     Could not parse revocation timestamp");
                                            }
                                        }
                                    }
                                }
                            }
                            _ => {
                                eprintln!("  [WARN] Signing key has unknown status: {}", key.status);
                            }
                        }

                        if key.is_demo {
                            eprintln!("  [WARN] DEMO KEY — do not trust for attribution");
                            eprintln!("     This key is intentionally public (Frame Me challenge).");
                            eprintln!("     Valid signature ≠ Victor's presence.");
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

            // Check seal key status (V2 sealed artifacts only)
            if artifact.version == vwh_core::format::ArtifactVersion::V2 {
                if let Some(seal_fp) = artifact.seal_fingerprint() {
                    let seal_fp_hex = seal_fp.to_hex();

                    // Revocation fast-exit before full display
                    if let Some(key) = keys.keys.iter().find(|k| k.fingerprint == seal_fp_hex) {
                        if key.status == "revoked" {
                            eprintln!("[REVOKED] The sealing key for this artifact has been revoked.");
                            std::process::exit(2);
                        }
                    }

                    let seal_entry = keys.keys.iter().find(|k| k.fingerprint == seal_fp_hex);
                    match seal_entry {
                        Some(key) => {
                            if let Some(ref label) = key.label {
                                println!("     Label:   {}", label);
                            }
                            println!("     Created: {}", key.created_at);

                            match key.status.as_str() {
                                "active" => {
                                    println!("  [OK] Sealing key recognized (active)\n");
                                }
                                "deprecated" => {
                                    match &key.deprecated_at {
                                        None => {
                                            eprintln!("  [WARN] Sealing key DEPRECATED");
                                            eprintln!("     Rotation timestamp unavailable — cannot time-gate");
                                        }
                                        Some(dep_at) => {
                                            match chrono::DateTime::parse_from_rfc3339(dep_at) {
                                                Ok(dep_ts) => {
                                                    if artifact.timestamp < dep_ts {
                                                        println!("  [OK] Sealing key deprecated after sealing — artifact valid");
                                                        println!("     Deprecated: {}\n", dep_at);
                                                    } else {
                                                        eprintln!("  [ERR] Artifact sealed AFTER key was deprecated — INVALID");
                                                        eprintln!("     Deprecated: {}", dep_at);
                                                        std::process::exit(2);
                                                    }
                                                }
                                                Err(_) => {
                                                    eprintln!("  [WARN] Sealing key DEPRECATED");
                                                    eprintln!("     Could not parse deprecation timestamp");
                                                }
                                            }
                                        }
                                    }
                                }
                                "revoked" => {
                                    // fast-exit already handled above; defensive branch
                                    match &key.revoked_at {
                                        None => {
                                            eprintln!("  [WARN] Sealing key REVOKED");
                                            eprintln!("     Revocation timestamp unavailable");
                                        }
                                        Some(rev_at) => {
                                            match chrono::DateTime::parse_from_rfc3339(rev_at) {
                                                Ok(rev_ts) => {
                                                    if artifact.timestamp < rev_ts {
                                                        eprintln!("  [WARN] Sealing key later revoked — artifact predates revocation");
                                                        eprintln!("     Revoked: {}", rev_at);
                                                    } else {
                                                        eprintln!("  [ERR] Artifact sealed AFTER key was revoked — INVALID");
                                                        eprintln!("     Revoked: {}", rev_at);
                                                        std::process::exit(2);
                                                    }
                                                }
                                                Err(_) => {
                                                    eprintln!("  [WARN] Sealing key REVOKED");
                                                    eprintln!("     Could not parse revocation timestamp");
                                                }
                                            }
                                        }
                                    }
                                }
                                _ => {
                                    eprintln!("  [WARN] Sealing key has unknown status: {}", key.status);
                                }
                            }

                            if key.is_demo {
                                eprintln!("  [WARN] DEMO KEY — do not trust for attribution");
                                eprintln!("     This key is intentionally public (Frame Me challenge).");
                                eprintln!("     Valid seal ≠ Victor's presence.");
                            }
                        }
                        None => {
                            println!("  [INFO] Sealing key not in registry");
                            println!("     This may be expected for private sealing keys\n");
                        }
                    }
                }
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
                            eprintln!("  [WARN] Ledger fingerprint mismatch");
                            eprintln!("     Ledger:   {}", entry.fingerprint);
                            eprintln!("     Artifact: {}", artifact_fp);
                        }
                    }
                    match entry.status.as_str() {
                        "revoked" => {
                            eprintln!("  [REVOKED] Artifact REVOKED");
                            if let Some(ref revoked_at) = entry.revoked_at {
                                eprintln!("     Revoked: {}", revoked_at);
                            }
                            if let Some(ref reason) = entry.reason {
                                eprintln!("     Reason:  {}", reason);
                            }
                            eprintln!("\n     Trust has been explicitly withdrawn for this artifact.");
                            std::process::exit(2);
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
                            eprintln!("  [WARN] Artifact has unknown ledger status: {}", entry.status);
                        }
                    }
                }
                None => {
                    if artifact.is_sealed() {
                        eprintln!("  [WARN] SUSPICIOUS");
                        eprintln!("     File claims to be Sealed, but is NOT in public ledger.");
                        eprintln!("     Possible tampering or embargo.");
                    } else {
                        eprintln!("  [WARN] UNPUBLISHED");
                        eprintln!("     Valid signature. Draft state. Not publicly acknowledged.");
                    }
                }
            }
        }
        RegistryStatus::Unavailable(reason) => {
            eprintln!("  [WARN] Registry unavailable: {}", reason);
            eprintln!("     Signature verification still valid");
            eprintln!("     Ledger status unknown");
            // ARCH-1: crypto passed but registry unavailable → exit(3)
            std::process::exit(3);
        }
    }


    Ok(())
}

pub fn note(file: &PathBuf) -> Result<()> {
    let bytes = fs::read(file).context("Failed to read artifact file")?;
    let artifact = Artifact::from_bytes(&bytes).context("Failed to parse artifact")?;

    if artifact.version != vwh_core::format::ArtifactVersion::V2 {
        anyhow::bail!("Notes are only supported for V2 artifacts (this is a V1 artifact)");
    }

    if !artifact.has_note_hash() {
        anyhow::bail!("This artifact has no note attached (note_hash is zero)");
    }

    let note_path = file.with_extension("vwh.note");

    if !note_path.exists() {
        anyhow::bail!(
            "Note sidecar file not found: {}\nNote hash is present in artifact but file is missing.",
            note_path.display()
        );
    }

    let note_bytes = fs::read(&note_path).context("Failed to read note file")?;
    let computed_hash = blake3::hash(&note_bytes);
    let hash_ok = computed_hash.as_bytes() == &artifact.note_hash;

    // CLI-C2: verify hash BEFORE displaying note content
    if !hash_ok {
        eprintln!("[ERR] Note hash mismatch — content may be tampered");
        eprintln!("[ERR] Expected: {}", hex::encode(artifact.note_hash));
        eprintln!("[ERR] Got:      {}", hex::encode(computed_hash.as_bytes()));
        std::process::exit(2);
    }

    // Strip any header block (e.g. `registry:`) and show only the body.
    let (headers, body) = crate::note_meta::parse_note(&note_bytes);

    println!();
    print_sep();
    println!("Note (BLAKE3 verified):\n");
    if let Some(reg) = headers.get("registry") {
        println!("Registry: {}\n", reg);
    }
    println!("---");
    println!("{}", body.trim());
    println!("---\n");

    print_sep();
    Ok(())
}

