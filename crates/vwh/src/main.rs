use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

mod commands;
mod inspect;
mod key;
mod migrate;
mod note_meta;
mod prompts;
mod registry;
mod state;

#[derive(Parser)]
#[command(name = "vwh")]
#[command(version)]
#[command(
    about = "VWH — cryptographic accountability for digital presence",
    long_about = "Create, sign, seal, and inspect .vwh artifacts. A single binary for both \
                  authors (who hold keys) and inspectors (who verify)."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    // ── Inspector (no keys required) ───────────────────────────────
    /// Inspect a .vwh artifact (verify signatures + registry status)
    Inspect {
        /// Path to .vwh file
        file: PathBuf,

        /// Skip registry check (offline mode)
        #[arg(long)]
        offline: bool,

        /// Custom registry base URL (overrides the artifact's own registry)
        #[arg(long, env = "VWH_REGISTRY_URL")]
        registry: Option<String>,
    },

    /// Display the note attached to a V2 artifact
    Note {
        /// Path to .vwh artifact file
        file: PathBuf,
    },

    // ── Authoring (requires keys in ~/.vwh) ────────────────────────
    /// Key management operations
    #[command(subcommand)]
    Key(KeyCommands),

    /// Revocation operations
    #[command(subcommand)]
    Revoke(RevokeCommands),

    /// Create a new unsigned .vwh draft
    Create {
        /// Intent (interactive prompt if not provided)
        #[arg(long)]
        intent: Option<String>,

        /// Output file path (interactive prompt if not provided)
        #[arg(long, short = 'o')]
        output: Option<PathBuf>,

        /// Use v1 format (128 bytes, no note) - default is v2
        #[arg(long)]
        v1: bool,
    },

    /// Sign an unsigned draft artifact
    Sign {
        /// Path to unsigned .vwh file
        file: PathBuf,

        /// Optional: specify which key to use for signing (default: active key)
        #[arg(long)]
        key: Option<String>,
    },

    /// Seal a signed artifact
    Seal {
        /// Path to signed .vwh file
        file: PathBuf,

        /// Sealing key to use (auto-selects if only one sealing key exists)
        #[arg(long)]
        key: Option<String>,
    },

    /// Unseal a sealed artifact (V2 only - removes seal signature)
    Unseal {
        /// Path to sealed .vwh file
        file: PathBuf,
    },

    /// Unsign a signed artifact (not sealed, not revoked)
    Unsign {
        /// Path to signed .vwh file
        file: PathBuf,
    },

    /// Edit draft artifact metadata
    Edit {
        /// Path to draft .vwh file
        file: PathBuf,

        /// New intent
        #[arg(long)]
        intent: Option<String>,

        /// New note
        #[arg(long)]
        note: Option<String>,
    },

    /// Dump local registry state as JSON
    Dump {
        /// What to dump
        #[arg(value_enum)]
        target: DumpTarget,
    },

    /// Push local registry to the remote git repo (GPG-signs the commit)
    Push,

    // ── First-class lifecycle (4.x — not yet implemented) ──────────
    /// First-time setup: generate/import keys, bootstrap registry
    Init,

    /// Manage existing vwh configuration
    Config,

    /// Rebase the local registry onto the remote
    Rebase,

    /// Back up the entire ~/.vwh (mandatory encryption)
    Export,

    /// Restore ~/.vwh from an encrypted backup
    Restore,
}

#[derive(Subcommand)]
enum KeyCommands {
    /// Initialize new Ed25519 identity key
    Init {
        /// Optional key name (auto-generated if not provided)
        name: Option<String>,

        /// Key type: 'signing' or 'sealing' (prompted if not provided)
        #[arg(long)]
        r#type: Option<String>,

        /// Optional label for the key
        #[arg(long)]
        label: Option<String>,
    },

    /// Display public key and fingerprint
    Show {
        /// Optional key name to show (shows active key if not provided)
        name: Option<String>,
    },

    /// Rotate to new key (mark current as deprecated)
    Rotate,
}

#[derive(Subcommand)]
enum RevokeCommands {
    /// Revoke a signing key
    Key {
        /// Revocation reason
        #[arg(long, required = true)]
        reason: String,

        /// Optional note
        #[arg(long)]
        note: Option<String>,
    },

    /// Revoke an artifact
    Artifact {
        /// Artifact ID (32-char hex)
        #[arg(required = true)]
        artifact_id: String,

        /// Revocation reason
        #[arg(long, required = true)]
        reason: String,

        /// Optional note
        #[arg(long)]
        note: Option<String>,
    },
}

#[derive(ValueEnum, Clone)]
pub enum DumpTarget {
    Keys,
    Ledger,
}

/// Stub handler for lifecycle commands not yet implemented in 4.0.0.
fn not_yet_implemented(cmd: &str) -> Result<()> {
    println!("vwh {cmd}: not yet implemented (coming in 4.x)");
    Ok(())
}

fn main() -> Result<()> {
    // One-time relocation of an existing ~/.config/vwh-author keystore into
    // ~/.vwh. Non-destructive and idempotent; safe to run on every invocation.
    migrate::ensure_migrated()?;

    let cli = Cli::parse();

    match cli.command {
        // Inspector
        Commands::Inspect { file, offline, registry } => inspect::inspect(file, offline, registry),
        Commands::Note { file } => {
            if let Err(e) = inspect::note(&file) {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
            Ok(())
        }

        // Keys
        Commands::Key(key_cmd) => match key_cmd {
            KeyCommands::Init { name, r#type, label } => {
                let type_str = match r#type {
                    Some(t) => t,
                    None => crate::prompts::prompt_key_type()?,
                };
                let key_type = match type_str.to_lowercase().as_str() {
                    "signing" => key::KeyType::Signing,
                    "sealing" => key::KeyType::Sealing,
                    _ => {
                        eprintln!("Error: Invalid key type '{}'. Must be 'signing' or 'sealing'.", type_str);
                        std::process::exit(1);
                    }
                };
                key::init(name, key_type, label)
            }
            KeyCommands::Show { name } => key::show(name),
            KeyCommands::Rotate => commands::key_rotate(),
        },

        // Revocation
        Commands::Revoke(revoke_cmd) => match revoke_cmd {
            RevokeCommands::Key { reason, note } => commands::key_revoke(reason, note),
            RevokeCommands::Artifact { artifact_id, reason, note } => {
                commands::artifact_revoke(artifact_id, reason, note)
            }
        },

        // Authoring
        Commands::Create { intent, output, v1 } => {
            let intent_str = match intent {
                Some(i) => i,
                None => prompts::prompt_intent()?.to_string(),
            };
            let output_path = match output {
                Some(o) => o,
                None => prompts::prompt_output("artifact.vwh")?,
            };
            commands::create_draft(intent_str, output_path, v1)
        }
        Commands::Sign { file, key } => commands::sign(file, key),
        Commands::Seal { file, key } => commands::seal(file, key),
        Commands::Unseal { file } => commands::unseal(file),
        Commands::Unsign { file } => commands::unsign(file),
        Commands::Edit { file, intent, note } => commands::edit(file, intent, note),
        Commands::Dump { target } => commands::dump(target),
        Commands::Push => commands::push_registry(),

        // Lifecycle stubs (4.x)
        Commands::Init => not_yet_implemented("init"),
        Commands::Config => not_yet_implemented("config"),
        Commands::Rebase => not_yet_implemented("rebase"),
        Commands::Export => not_yet_implemented("export"),
        Commands::Restore => not_yet_implemented("restore"),
    }
}
