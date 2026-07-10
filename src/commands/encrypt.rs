use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::commands::{aad_for, enc_path, strip_enc};
use crate::crypto::{self, KeyMode, SALT_LEN};
use crate::keystore::KeySource;
use crate::manifest::{rel_to_root, require_project};

pub fn encrypt(paths: Vec<PathBuf>, keep: bool) -> Result<()> {
    let (root, mut manifest) = require_project()?;

    let targets = if paths.is_empty() {
        manifest.paths()
    } else {
        let mut targets = Vec::new();
        for path in paths {
            let rel = strip_enc(rel_to_root(&root, &path)?);
            manifest.add(rel.clone());
            targets.push(rel);
        }
        manifest.save(&root)?;
        targets
    };
    if targets.is_empty() {
        bail!("no env files in the manifest; pass paths to encrypt, e.g. `symmetry encrypt .env`");
    }

    let mut keys = KeySource::new(&manifest.project_id);
    let encrypted = encrypt_targets(&root, &mut keys, &targets, keep)?;
    if encrypted > 0 && keep {
        println!("Plaintext files kept (--keep); remember they're still on disk.");
    }
    Ok(())
}

/// Encrypt each target (root-relative) to its .enc sibling, removing the
/// plaintext unless `keep`. Also used by `init` for encrypt-on-setup.
pub(super) fn encrypt_targets(
    root: &Path,
    keys: &mut KeySource,
    targets: &[PathBuf],
    keep: bool,
) -> Result<usize> {
    let keychain_key = keys.try_keychain()?;

    let mut encrypted = 0usize;
    for rel in targets {
        let plain = root.join(rel);
        let enc = enc_path(&plain);
        if !plain.exists() {
            if enc.exists() {
                println!("{}: already encrypted", rel.display());
            } else {
                eprintln!("warning: {} not found, skipping", rel.display());
            }
            continue;
        }

        let plaintext = std::fs::read(&plain)
            .with_context(|| format!("failed to read {}", plain.display()))?;
        let aad = aad_for(rel);
        let encfile = match keychain_key {
            Some(key) => crypto::seal(&key, &plaintext, &aad, KeyMode::Keychain)?,
            None => {
                let password = keys.password(true)?.to_string();
                let salt = crypto::random_bytes::<SALT_LEN>();
                let key = crypto::derive_key(&password, &salt)?;
                crypto::seal(&key, &plaintext, &aad, KeyMode::Password { salt })?
            }
        };
        std::fs::write(&enc, encfile.render())
            .with_context(|| format!("failed to write {}", enc.display()))?;
        if !keep {
            std::fs::remove_file(&plain)
                .with_context(|| format!("failed to remove {}", plain.display()))?;
        }
        println!("encrypted {} -> {}.enc", rel.display(), rel.display());
        encrypted += 1;
    }
    Ok(encrypted)
}
