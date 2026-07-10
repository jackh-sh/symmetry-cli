use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use zeroize::Zeroize;

use crate::auth;
use crate::commands::encrypt::encrypt_targets;
use crate::crypto::{self, KEY_LEN};
use crate::keystore::{self, KeySource};
use crate::manifest::{MANIFEST_NAME, Manifest, find_root};
use crate::scan;

const GITIGNORE_BLOCK: &str = "\
# symmetry: keep plaintext env files out of git, but commit encrypted ones
.env
.env.*
!*.enc
!.env.example
!.env.sample
!.env.template
";

enum KeyChoice {
    Keychain { strict: bool },
    Password,
}

pub fn init(password: bool, strict: bool, yes: bool) -> Result<()> {
    let cwd = std::env::current_dir()?;
    if let Some(existing) = find_root(&cwd) {
        bail!(
            "already initialized: {}",
            existing.join(MANIFEST_NAME).display()
        );
    }
    let interactive = !yes && std::io::stdin().is_terminal();

    let found = scan::scan(&cwd)?;
    let selected = choose_files(found, interactive)?;
    let manifest = Manifest::new(selected.clone());

    let choice = if password {
        KeyChoice::Password
    } else if strict {
        require_strict_support()?;
        KeyChoice::Keychain { strict: true }
    } else if interactive {
        let mut items = vec![
            "System keychain (recommended): random key, unlocked with your login",
            "Password (less secure): you type it every time symmetry needs the key",
        ];
        if auth::supported() {
            items.insert(
                1,
                "System keychain, strict: Touch ID / Windows Hello / account password on every use",
            );
        }
        let picked = dialoguer::Select::new()
            .with_prompt("Where should the encryption key live?")
            .items(&items)
            .default(0)
            .interact()?;
        if picked == items.len() - 1 {
            KeyChoice::Password
        } else {
            KeyChoice::Keychain { strict: picked == 1 }
        }
    } else {
        KeyChoice::Keychain { strict: false }
    };

    match choice {
        KeyChoice::Password => {
            println!("Password mode: you'll choose a password the first time you encrypt.");
        }
        KeyChoice::Keychain { strict } => {
            let mut key = crypto::random_bytes::<KEY_LEN>();
            let stored = keystore::store_key(&manifest.project_id, &key, strict);
            key.zeroize();
            match stored {
                Ok(()) if strict => println!(
                    "Generated an encryption key in the system keychain (strict mode: \
                     every use requires user verification)."
                ),
                Ok(()) => println!(
                    "Generated an encryption key and stored it in the system keychain."
                ),
                Err(err) => {
                    eprintln!("warning: {err:#}");
                    println!("Falling back to password mode: you'll choose a password when encrypting.");
                }
            }
        }
    }

    manifest.save(&cwd)?;
    println!("Wrote {MANIFEST_NAME}");
    update_gitignore(&cwd)?;

    if selected.is_empty() {
        println!("No .env files found. Create one and run `symmetry encrypt <path>` to manage it.");
        return Ok(());
    }
    println!("Managing {} env file(s):", selected.len());
    for file in &selected {
        println!("  {}", file.display());
    }

    let encrypt_now = if yes {
        true
    } else if interactive {
        dialoguer::Confirm::new()
            .with_prompt(format!(
                "Encrypt {} file(s) now? Plaintext will be replaced by .enc files",
                selected.len()
            ))
            .default(true)
            .interact()?
    } else {
        false
    };

    if encrypt_now {
        let mut keys = KeySource::new(&manifest.project_id);
        encrypt_targets(&cwd, &mut keys, &selected, false)?;
    } else {
        println!("Run `symmetry encrypt` when you're ready to encrypt them.");
    }
    Ok(())
}

pub(super) fn require_strict_support() -> Result<()> {
    if !auth::supported() {
        bail!("strict mode is not supported on this platform yet (macOS and Windows only)");
    }
    Ok(())
}

fn choose_files(found: Vec<PathBuf>, interactive: bool) -> Result<Vec<PathBuf>> {
    if found.len() <= 1 || !interactive {
        return Ok(found);
    }
    let items: Vec<String> = found.iter().map(|p| p.display().to_string()).collect();
    let picks = dialoguer::MultiSelect::new()
        .with_prompt("Select the env files to manage (space toggles, enter confirms)")
        .items(&items)
        .defaults(&vec![true; items.len()])
        .interact()?;
    if picks.is_empty() {
        bail!("no env files selected");
    }
    Ok(picks.into_iter().map(|i| found[i].clone()).collect())
}

fn update_gitignore(root: &Path) -> Result<()> {
    let path = root.join(".gitignore");
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    if existing.contains("# symmetry:") {
        return Ok(());
    }
    let mut out = existing;
    if !out.is_empty() {
        if !out.ends_with('\n') {
            out.push('\n');
        }
        out.push('\n');
    }
    out.push_str(GITIGNORE_BLOCK);
    std::fs::write(&path, out).context("failed to update .gitignore")?;
    println!("Updated .gitignore (plaintext env files stay ignored, *.enc gets committed)");
    Ok(())
}
