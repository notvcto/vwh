//! One-time, non-destructive relocation of a pre-4.0 keystore.
//!
//! Versions <= 3.x stored author state under the platform config dir for
//! `vwh-author` (e.g. `~/.config/vwh-author` on Linux), with each key in a
//! top-level subdirectory plus `keys.json`, `ledger.json`, and a `registry/`
//! clone. 4.0 moves everything to `~/.vwh`, with keys nested under `keys/`.
//!
//! This copies the old layout into the new one. It NEVER deletes or modifies
//! the originals, and it is a no-op once `~/.vwh` is populated, so running it
//! on every invocation is safe.

use anyhow::{Context, Result};
use directories::ProjectDirs;
use std::fs;
use std::path::Path;

use crate::key::{get_config_dir, get_keys_dir};

const KEY_FILENAME: &str = "identity.key.enc";

/// Migrate `~/.config/vwh-author` → `~/.vwh` if needed. Idempotent.
pub fn ensure_migrated() -> Result<()> {
    let new_home = get_config_dir()?;

    // Already migrated / fresh 4.0 install: do nothing.
    if new_home.join("keys.json").exists() || new_home.join("keys").is_dir() {
        return Ok(());
    }

    // Locate the legacy config dir; if absent there is nothing to migrate.
    let old_home = match ProjectDirs::from("", "", "vwh-author") {
        Some(p) => p.config_dir().to_path_buf(),
        None => return Ok(()),
    };
    if !old_home.is_dir() {
        return Ok(());
    }

    let entries = match fs::read_dir(&old_home) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };

    let new_keys = get_keys_dir()?;
    let mut migrated_keys = 0usize;
    let mut migrated_state = false;

    for entry in entries.flatten() {
        let path = entry.path();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };

        if path.is_file() && (name == "keys.json" || name == "ledger.json") {
            fs::create_dir_all(&new_home)?;
            fs::copy(&path, new_home.join(&name))
                .with_context(|| format!("Failed to copy {name} during migration"))?;
            migrated_state = true;
        } else if path.is_dir() && name == "registry" {
            copy_dir_all(&path, &new_home.join("registry"))
                .context("Failed to copy registry/ during migration")?;
        } else if path.is_dir() && path.join(KEY_FILENAME).exists() {
            // A key directory.
            copy_dir_all(&path, &new_keys.join(&name))
                .with_context(|| format!("Failed to copy key '{name}' during migration"))?;
            migrated_keys += 1;
        }
    }

    if migrated_keys > 0 || migrated_state {
        println!(
            "[migrate] Imported existing keystore into {}",
            new_home.display()
        );
        println!(
            "[migrate]   {migrated_keys} key(s) moved under keys/. Originals left untouched at:"
        );
        println!("[migrate]   {}", old_home.display());
        println!("[migrate]   Remove the old directory once you've verified the new one.\n");
    }

    Ok(())
}

/// Recursively copy `src` into `dst` (creating `dst`). Files are overwritten.
fn copy_dir_all(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_all(&from, &to)?;
        } else {
            fs::copy(&from, &to)?;
        }
    }
    Ok(())
}
