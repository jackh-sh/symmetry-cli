use anyhow::Result;
use console::measure_text_width;

use crate::commands::enc_path;
use crate::keystore;
use crate::manifest::require_project;
use crate::scan;
use crate::ui;

pub fn status() -> Result<()> {
    let (root, manifest) = require_project()?;

    match keystore::load_key(&manifest.project_id) {
        Ok(Some(stored)) if stored.strict => {
            ui::ok("Key: system keychain");
            ui::detail("Strict mode: verification on every use.");
        }
        Ok(Some(_)) => ui::ok("Key: system keychain"),
        Ok(None) => {
            ui::item("Key: password mode (no key in keychain)");
            ui::detail("Import a shared key with `symmetry key import <key>`.");
        }
        Err(err) => ui::warn(format!("{err:#}")),
    }

    if manifest.files.is_empty() {
        ui::heading("No env files in the manifest");
    } else {
        ui::heading("Managed env files");
        let paths = manifest.paths();
        let width = paths
            .iter()
            .map(|p| measure_text_width(&p.display().to_string()))
            .max()
            .unwrap_or(0);
        for rel in paths {
            let plain = root.join(&rel).exists();
            let enc = enc_path(&root.join(&rel)).exists();
            let label = match (enc, plain) {
                (true, false) => "locked",
                (true, true) => "locked + plaintext on disk",
                (false, true) => "unlocked",
                (false, false) => "missing",
            };
            let name = rel.display().to_string();
            let pad = " ".repeat(width.saturating_sub(measure_text_width(&name)));
            println!("  {}{pad}  {}", ui::path(&name), ui::state(label));
        }
    }

    let unmanaged: Vec<_> = scan::scan(&root)?
        .into_iter()
        .filter(|found| !manifest.contains(found))
        .collect();
    if !unmanaged.is_empty() {
        ui::heading("Unmanaged env files");
        ui::detail("Add with `symmetry encrypt <path>`.");
        for rel in unmanaged {
            ui::item(ui::path(rel.display()));
        }
    }
    Ok(())
}
