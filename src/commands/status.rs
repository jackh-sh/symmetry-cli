use anyhow::Result;

use crate::commands::enc_path;
use crate::manifest::require_project;
use crate::scan;

pub fn status() -> Result<()> {
    let (root, manifest) = require_project()?;

    if manifest.files.is_empty() {
        println!("No env files in the manifest.");
    } else {
        println!("Managed env files:");
        for rel in manifest.paths() {
            let plain = root.join(&rel).exists();
            let enc = enc_path(&root.join(&rel)).exists();
            let state = match (enc, plain) {
                (true, false) => "locked",
                (true, true) => "locked + plaintext on disk",
                (false, true) => "unlocked",
                (false, false) => "missing",
            };
            println!("  {:<40} {}", rel.display().to_string(), state);
        }
    }

    let unmanaged: Vec<_> = scan::scan(&root)?
        .into_iter()
        .filter(|found| !manifest.contains(found))
        .collect();
    if !unmanaged.is_empty() {
        println!("\nUnmanaged env files (add with `symmetry encrypt <path>`):");
        for rel in unmanaged {
            println!("  {}", rel.display());
        }
    }
    Ok(())
}
