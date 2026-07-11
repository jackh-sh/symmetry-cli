use std::path::PathBuf;

use anyhow::{Context, Result, bail};

use crate::commands::{decrypt_entry, enc_path, strip_enc};
use crate::fsutil;
use crate::keystore::KeySource;
use crate::manifest::{rel_to_root, require_project};
use crate::ui;

pub fn decrypt(paths: Vec<PathBuf>, force: bool) -> Result<()> {
    let (root, manifest) = require_project()?;

    let targets = if paths.is_empty() {
        manifest.paths()
    } else {
        paths
            .into_iter()
            .map(|p| Ok(strip_enc(rel_to_root(&root, &p)?)))
            .collect::<Result<Vec<_>>>()?
    };
    if targets.is_empty() {
        bail!("no env files in the manifest");
    }

    let mut keys = KeySource::new(&manifest.project_id);
    for rel in targets {
        let plain = root.join(&rel);
        if !enc_path(&plain).exists() {
            ui::warn(format!(
                "no encrypted file for {}, skipping",
                ui::path(rel.display())
            ));
            continue;
        }
        let plaintext = decrypt_entry(&root, &rel, &mut keys)?;
        if plain.exists() {
            let existing = std::fs::read(&plain)
                .with_context(|| format!("failed to read {}", plain.display()))?;
            if existing == plaintext {
                ui::detail(format!("{} already decrypted", rel.display()));
                continue;
            }
            if !force {
                bail!(
                    "{} exists and differs from the encrypted version; use --force to overwrite it",
                    rel.display()
                );
            }
        }
        fsutil::write_secret(&plain, &plaintext)?;
        ui::ok(format!("decrypted {}", ui::path(rel.display())));
    }
    Ok(())
}
