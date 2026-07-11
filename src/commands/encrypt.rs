use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::commands::{aad_for, enc_path, strip_enc};
use crate::crypto::{self, KeyMode};
use crate::keystore::{KeySource, PASSWORD_ENV};
use crate::manifest::{rel_to_root, require_project};
use crate::ui;

pub fn encrypt(paths: Vec<PathBuf>, keep: bool) -> Result<()> {
    let (root, mut manifest) = require_project()?;

    let explicit = !paths.is_empty();
    let targets = if explicit {
        paths
            .into_iter()
            .map(|p| Ok(strip_enc(rel_to_root(&root, &p)?)))
            .collect::<Result<Vec<_>>>()?
    } else {
        manifest.paths()
    };
    if targets.is_empty() {
        bail!("no env files in the manifest; pass paths to encrypt, e.g. `symmetry encrypt .env`");
    }

    let mut keys = KeySource::new(&manifest.project_id);
    let encrypted = encrypt_targets(&root, &mut keys, &targets, keep)?;

    // Record explicitly passed paths only once they have an .enc file, so a
    // failed run or a typo'd path doesn't end up in the manifest.
    if explicit {
        let mut changed = false;
        for rel in &targets {
            if enc_path(&root.join(rel)).exists() && !manifest.contains(rel) {
                manifest.add(rel.clone());
                changed = true;
            }
        }
        if changed {
            manifest.save(&root)?;
        }
    }

    if encrypted > 0 && keep {
        ui::warn("Plaintext files kept (--keep); remember they're still on disk.");
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
    // No key in a working keychain means password mode. A keychain *error*
    // must not silently downgrade the project to password encryption; only
    // an explicit SYMMETRY_PASSWORD (e.g. keychain-less CI) allows that.
    let keychain_key = match keys.try_keychain() {
        Ok(key) => key,
        Err(err) if keys.keychain_errored() && std::env::var_os(PASSWORD_ENV).is_some() => {
            ui::warn(format!("{err:#}; using password mode ({PASSWORD_ENV} is set)"));
            None
        }
        Err(err) if keys.keychain_errored() => {
            return Err(err.context(format!(
                "cannot read the system keychain; fix it, or set {PASSWORD_ENV} to encrypt \
                 with a password instead"
            )));
        }
        Err(err) => return Err(err),
    };

    let mut encrypted = 0usize;
    for rel in targets {
        let plain = root.join(rel);
        let enc = enc_path(&plain);
        if !plain.exists() {
            if enc.exists() {
                ui::detail(format!("{} already encrypted", rel.display()));
            } else {
                ui::warn(format!("{} not found, skipping", ui::path(rel.display())));
            }
            continue;
        }

        let plaintext = std::fs::read(&plain)
            .with_context(|| format!("failed to read {}", plain.display()))?;
        let aad = aad_for(rel)?;
        let encfile = match &keychain_key {
            Some(key) => crypto::seal(key, &plaintext, &aad, KeyMode::Keychain)?,
            None => {
                let (mode, key) = keys.new_password_key()?;
                crypto::seal(&key, &plaintext, &aad, mode)?
            }
        };
        crate::fsutil::write_atomic(&enc, encfile.render().as_bytes(), false)?;
        if !keep {
            std::fs::remove_file(&plain)
                .with_context(|| format!("failed to remove {}", plain.display()))?;
        }
        ui::ok(format!(
            "encrypted {} {} {}",
            ui::path(rel.display()),
            ui::dim("→"),
            ui::path(format!("{}.enc", rel.display()))
        ));
        encrypted += 1;
    }
    Ok(encrypted)
}
