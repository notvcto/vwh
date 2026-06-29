use anyhow::{Context, Result};
use console::Style;
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Select};
use std::collections::HashMap;
use std::path::PathBuf;
use vwh_core::Intent;

use crate::registry::KeyEntryV2;

/// Prompt for intent if not provided
pub fn prompt_intent() -> Result<Intent> {
    let items = vec![
        "lab              - Laboratory/testing environment",
        "owned-infra      - Owned infrastructure deployment",
        "auth-redteam     - Authorized red team engagement",
        "blue-remediation - Blue team remediation work",
        "research         - Security research",
    ];

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select artifact intent")
        .items(&items)
        .default(0)
        .interact()
        .context("Failed to get intent selection")?;

    let intent = match selection {
        0 => Intent::Lab,
        1 => Intent::OwnedInfra,
        2 => Intent::AuthRedteam,
        3 => Intent::BlueRemediation,
        4 => Intent::Research,
        _ => unreachable!(),
    };

    Ok(intent)
}

/// Prompt for output path if not provided
pub fn prompt_output(default: &str) -> Result<PathBuf> {
    let path: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Output file path")
        .default(default.to_string())
        .interact_text()
        .context("Failed to get output path")?;

    Ok(PathBuf::from(path))
}

/// Prompt for note (v2 artifacts)
pub fn prompt_note() -> Result<String> {
    println!();
    let cyan = Style::new().cyan().bold();
    println!("{}", cyan.apply_to("NOTE (REQUIRED):"));
    println!("Enter a human-readable description for this artifact.");
    println!("This will be stored in a separate .vwh.note file.");
    println!();

    let note: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Note")
        .interact_text()
        .context("Failed to get note")?;

    if note.trim().is_empty() {
        anyhow::bail!("Note cannot be empty for v2 artifacts");
    }

    Ok(note.trim().to_string())
}

/// Prompt for key type (signing or sealing)
pub fn prompt_key_type() -> Result<String> {
    let items = vec![
        "signing  - Signs artifact content (author identity)",
        "sealing  - Seals signed artifacts (immutable stamp)",
    ];

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Key type")
        .items(&items)
        .default(0)
        .interact()
        .context("Failed to get key type")?;

    Ok(match selection {
        0 => "signing".to_string(),
        1 => "sealing".to_string(),
        _ => unreachable!(),
    })
}

/// Prompt for a human-readable key label
pub fn prompt_key_label(key_type: &str) -> Result<String> {
    println!();
    let cyan = Style::new().cyan().bold();
    println!("{}", cyan.apply_to("KEY LABEL:"));
    println!("A short human-readable name for this key (e.g. \"main signing key\", \"prod seal\").");
    println!("This is what appears in 'dump keys' and key selection menus.");
    println!();

    let label: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Label")
        .default(format!("my {} key", key_type))
        .interact_text()
        .context("Failed to get key label")?;

    Ok(label.trim().to_string())
}

/// Build a map from fingerprint hex to key directory name by scanning the keys dir once.
fn build_fingerprint_name_map() -> Result<HashMap<String, String>> {
    use crate::key::get_keys_dir;
    use std::convert::TryInto;
    use std::fs;

    let keys_dir = get_keys_dir()?;
    let mut map = HashMap::new();

    if let Ok(entries) = fs::read_dir(&keys_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let pubkey_file = path.join("identity.pub");
                if pubkey_file.exists() {
                    if let Ok(pubkey_hex) = fs::read_to_string(&pubkey_file) {
                        if let Ok(pubkey_bytes) = hex::decode(pubkey_hex.trim()) {
                            if let Ok(pubkey_array) = TryInto::<[u8; 32]>::try_into(pubkey_bytes) {
                                let fp = vwh_core::KeyFingerprint::new(&pubkey_array);
                                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                                    map.insert(fp.to_hex(), name.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(map)
}

/// Select a key from a list (signing or sealing)
pub fn select_key(keys: &[KeyEntryV2], key_type: &str) -> Result<String> {
    if keys.is_empty() {
        anyhow::bail!(
            "No {} keys found.\n\nCreate one with: vwh key init --type {}",
            key_type,
            key_type
        );
    }

    // Build fingerprint→name map once for this call
    let fp_map = build_fingerprint_name_map()?;

    if keys.len() == 1 {
        // Auto-select if only one key
        println!("Auto-selected {} key: {}\n", key_type, keys[0].label);
        return fp_map
            .get(&keys[0].fingerprint)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Could not find key directory for fingerprint"));
    }

    // Multiple keys - show selection menu
    let items: Vec<String> = keys
        .iter()
        .map(|k| format!("{} ({})", k.label, k.fingerprint.chars().take(16).collect::<String>()))
        .collect();

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt(format!("Select {} key", key_type))
        .items(&items)
        .default(0)
        .interact()
        .context("Failed to select key")?;

    fp_map
        .get(&keys[selection].fingerprint)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("Could not find key directory for fingerprint"))
}

/// Select a key for rotation — always prompts, never auto-selects.
/// Shows all active keys regardless of type so the user can pick which to rotate.
pub fn select_key_for_rotation(keys: &[KeyEntryV2]) -> Result<String> {
    if keys.is_empty() {
        anyhow::bail!("No active keys found.\n\nCreate one with: vwh key init");
    }

    // Build fingerprint→name map once for this call
    let fp_map = build_fingerprint_name_map()?;

    let items: Vec<String> = keys
        .iter()
        .map(|k| format!("[{}] {} ({}...)", k.key_type, k.label, k.fingerprint.chars().take(16).collect::<String>()))
        .collect();

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select key to rotate")
        .items(&items)
        .default(0)
        .interact()
        .context("Failed to select key")?;

    let key_name = fp_map
        .get(&keys[selection].fingerprint)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("Could not find key directory for fingerprint"))?;

    let confirmed = Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("This operation is irreversible. Proceed?")
        .interact()
        .context("Failed to get confirmation")?;
    if !confirmed {
        return Err(anyhow::anyhow!("Operation cancelled by user"));
    }

    Ok(key_name)
}

/// Print success box with artifact details
pub fn print_success_box(title: &str, details: &[(&str, String)]) {
    let green = Style::new().green().bold();
    let cyan = Style::new().cyan();

    println!();
    println!("{}", green.apply_to("╭─────────────────────────────────────────────────╮"));
    println!("{} {} {}", 
        green.apply_to("│"),
        green.apply_to(format!("✓ {:<44}", title)),
        green.apply_to("│")
    );
    println!("{}", green.apply_to("├─────────────────────────────────────────────────┤"));

    for (key, value) in details {
        let display_value = if value.len() > 35 {
            format!("{}...", &value[..32])
        } else {
            value.clone()
        };
        println!("{} {}: {:<36} {}",
            green.apply_to("│"),
            cyan.apply_to(format!("{:<10}", key)),
            display_value,
            green.apply_to("│")
        );
    }

    println!("{}", green.apply_to("╰─────────────────────────────────────────────────╯"));
    println!();
}

/// Print error box
#[allow(dead_code)] // used by upcoming init/config commands (4.x)
pub fn print_error(message: &str) {
    let red = Style::new().red().bold();
    eprintln!();
    eprintln!("{} {}", red.apply_to("✗ Error:"), message);
    eprintln!();
}

/// Print warning box
#[allow(dead_code)] // used by upcoming init/config commands (4.x)
pub fn print_warning(message: &str) {
    let yellow = Style::new().yellow().bold();
    eprintln!();
    eprintln!("{} {}", yellow.apply_to("⚠ Warning:"), message);
    eprintln!();
}
