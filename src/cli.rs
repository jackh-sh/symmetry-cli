use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "symmetry",
    version,
    about = "Encrypt .env files and inject them into processes at runtime"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Scan for .env files, create symmetry.toml, and set up an encryption key
    Init {
        /// Use a password instead of storing a key in the system keychain
        #[arg(long)]
        password: bool,
        /// Skip prompts: manage every env file found and encrypt immediately
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Encrypt env files to .enc siblings (alias: lock)
    #[command(alias = "lock")]
    Encrypt {
        /// Specific env files to encrypt (default: everything in the manifest)
        paths: Vec<PathBuf>,
        /// Keep the plaintext file after encrypting
        #[arg(long)]
        keep: bool,
    },
    /// Restore plaintext env files from their .enc siblings (alias: unlock)
    #[command(alias = "unlock")]
    Decrypt {
        /// Specific env files to decrypt (default: everything in the manifest)
        paths: Vec<PathBuf>,
        /// Overwrite an existing plaintext file that differs from the encrypted version
        #[arg(long)]
        force: bool,
    },
    /// Run a command with decrypted env vars injected (never writes plaintext to disk)
    Run {
        /// Env file to inject (default: the one nearest to the current directory)
        #[arg(long)]
        file: Option<PathBuf>,
        /// Inject every env file in the manifest, in manifest order
        #[arg(long, conflicts_with = "file")]
        all: bool,
        /// Command to run, after `--` (e.g. `symmetry run -- npm start`)
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Show the encryption state of each managed env file
    Status,
    /// Export or import the project encryption key
    Key {
        #[command(subcommand)]
        action: KeyAction,
    },
}

#[derive(Subcommand)]
pub enum KeyAction {
    /// Print the project key as base64 (for sharing with a teammate over a secure channel)
    Export,
    /// Store a shared project key in this machine's keychain
    Import {
        /// Base64 key from `symmetry key export`
        key: String,
    },
}
