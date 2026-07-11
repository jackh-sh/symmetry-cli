use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use zeroize::Zeroizing;

use crate::auth;
use crate::commands::encrypt::encrypt_targets;
use crate::crypto::{self, KEY_LEN};
use crate::keystore::{self, KeySource};
use crate::manifest::{MANIFEST_NAME, Manifest, find_root};
use crate::scan;
use crate::ui;

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
    let theme = dialoguer::theme::ColorfulTheme::default();

    ui::banner(
        "symmetry",
        "Encrypt your .env files and inject them into processes at runtime.",
    );

    // Step 1: which env files to manage.
    ui::step(1, 3, "Files to manage");
    let found = scan::scan(&cwd)?;
    let selected = choose_files(found, interactive, &theme)?;
    if selected.is_empty() {
        ui::detail("No .env files found in this directory yet.");
    } else {
        for file in &selected {
            ui::item(ui::path(file.display()));
        }
    }
    let manifest = Manifest::new(selected.clone());

    // Step 2: where the encryption key lives.
    ui::step(2, 3, "Encryption key");
    let choice = choose_key(password, strict, interactive, &theme)?;
    store_key_for(&choice, &manifest)?;

    manifest.save(&cwd)?;
    ui::ok(format!("Wrote {}", ui::path(MANIFEST_NAME)));
    update_gitignore(&cwd)?;

    // Step 3: encrypt now (or defer).
    ui::step(3, 3, "Encrypt");
    if selected.is_empty() {
        ui::detail("Nothing to encrypt yet.");
        summary(&selected, false);
        return Ok(());
    }
    let encrypt_now = if yes {
        true
    } else if interactive {
        dialoguer::Confirm::with_theme(&theme)
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
        println!();
        let mut keys = KeySource::new(&manifest.project_id);
        encrypt_targets(&cwd, &mut keys, &selected, false)?;
    } else {
        ui::detail("Skipped. Encrypt them whenever you're ready.");
    }

    summary(&selected, encrypt_now);
    Ok(())
}

/// Decide where the key lives, prompting when interactive.
fn choose_key(
    password: bool,
    strict: bool,
    interactive: bool,
    theme: &dialoguer::theme::ColorfulTheme,
) -> Result<KeyChoice> {
    if password {
        return Ok(KeyChoice::Password);
    }
    if strict {
        require_strict_support()?;
        return Ok(KeyChoice::Keychain { strict: true });
    }
    if !interactive {
        return Ok(KeyChoice::Keychain { strict: false });
    }

    let mut items = vec![
        "System keychain (recommended) — random key, unlocked with your login",
        "Password (less secure) — typed every time symmetry needs the key",
    ];
    if auth::supported() {
        items.insert(
            1,
            "System keychain, strict — Touch ID / Windows Hello on every use",
        );
    }
    let picked = dialoguer::Select::with_theme(theme)
        .with_prompt("Where should the encryption key live?")
        .items(&items)
        .default(0)
        .interact()?;
    if picked == items.len() - 1 {
        Ok(KeyChoice::Password)
    } else {
        Ok(KeyChoice::Keychain { strict: picked == 1 })
    }
}

/// Generate and store the key (or announce password mode).
fn store_key_for(choice: &KeyChoice, manifest: &Manifest) -> Result<()> {
    match choice {
        KeyChoice::Password => {
            ui::ok("Password mode: you'll choose a password the first time you encrypt.");
        }
        KeyChoice::Keychain { strict } => {
            let key = Zeroizing::new(crypto::random_bytes::<KEY_LEN>());
            let stored = keystore::store_key(&manifest.project_id, &key, *strict);
            match stored {
                Ok(()) if *strict => {
                    ui::ok("Generated an encryption key in the system keychain.");
                    ui::detail("Strict mode: every use requires user verification.");
                }
                Ok(()) => {
                    ui::ok("Generated an encryption key and stored it in the system keychain.");
                }
                Err(err) => {
                    ui::warn(format!("{err:#}"));
                    ui::detail(
                        "Falling back to password mode: you'll choose a password when encrypting.",
                    );
                }
            }
        }
    }
    Ok(())
}

/// Closing summary with next-step hints.
fn summary(selected: &[PathBuf], encrypted: bool) {
    ui::done("Setup complete");
    if selected.is_empty() {
        ui::hint(format!(
            "Add a file: {}",
            ui::strong("symmetry encrypt <path>")
        ));
        return;
    }
    if !encrypted {
        ui::hint(format!("Encrypt now: {}", ui::strong("symmetry encrypt")));
    }
    ui::hint(format!(
        "Run a command with secrets injected: {}",
        ui::strong("symmetry run -- <cmd>")
    ));
    ui::hint(format!("Inspect variables: {}", ui::strong("symmetry show")));
}

pub(super) fn require_strict_support() -> Result<()> {
    if !auth::supported() {
        bail!("strict mode is not supported on this platform yet (macOS and Windows only)");
    }
    Ok(())
}

fn choose_files(
    found: Vec<PathBuf>,
    interactive: bool,
    theme: &dialoguer::theme::ColorfulTheme,
) -> Result<Vec<PathBuf>> {
    if found.len() <= 1 || !interactive {
        return Ok(found);
    }
    let items: Vec<String> = found.iter().map(|p| p.display().to_string()).collect();
    let picks = dialoguer::MultiSelect::with_theme(theme)
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
    ui::ok(format!(
        "Updated {} (plaintext env files stay ignored, *.enc gets committed)",
        ui::path(".gitignore")
    ));
    Ok(())
}
