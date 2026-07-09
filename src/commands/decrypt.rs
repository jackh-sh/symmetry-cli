use std::path::PathBuf;

use anyhow::{Context, Result, bail};

use crate::commands::{decrypt_entry, enc_path, strip_enc};
use crate::keystore::KeySource;
use crate::manifest::{rel_to_root, require_project};

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
            eprintln!("warning: no encrypted file for {}, skipping", rel.display());
            continue;
        }
        let plaintext = decrypt_entry(&root, &rel, &mut keys)?;
        if plain.exists() {
            let existing = std::fs::read(&plain)?;
            if existing == plaintext {
                println!("{}: already decrypted", rel.display());
                continue;
            }
            if !force {
                bail!(
                    "{} exists and differs from the encrypted version; use --force to overwrite it",
                    rel.display()
                );
            }
        }
        std::fs::write(&plain, &plaintext)
            .with_context(|| format!("failed to write {}", plain.display()))?;
        println!("decrypted {}", rel.display());
    }
    Ok(())
}
