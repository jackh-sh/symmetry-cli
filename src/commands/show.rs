use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

use crate::commands::{decrypt_entry, enc_path, strip_enc};
use crate::envfile;
use crate::keystore::KeySource;
use crate::manifest::{rel_to_root, require_project};
use crate::ui;

pub fn show(path: Option<PathBuf>, reveal: bool) -> Result<()> {
    let (root, manifest) = require_project()?;

    let filter = match path {
        Some(p) => strip_enc(rel_to_root(&root, &p)?),
        None => {
            let cwd = std::env::current_dir()?;
            cwd.strip_prefix(&root).unwrap_or(Path::new("")).to_path_buf()
        }
    };
    let targets: Vec<PathBuf> = manifest
        .paths()
        .into_iter()
        .filter(|f| *f == filter || f.starts_with(&filter))
        .collect();
    if targets.is_empty() {
        bail!(
            "no managed env files under {}; see `symmetry status`",
            if filter.as_os_str().is_empty() {
                "the project root".to_string()
            } else {
                filter.display().to_string()
            }
        );
    }

    let mut keys = KeySource::new(&manifest.project_id);
    for rel in targets {
        let plain = root.join(&rel);
        let (bytes, state) = if enc_path(&plain).exists() {
            (decrypt_entry(&root, &rel, &mut keys)?, "locked")
        } else if plain.exists() {
            (std::fs::read(&plain)?, "unlocked")
        } else {
            ui::warn(format!("{} is missing, skipping", ui::path(rel.display())));
            continue;
        };

        println!("\n{} ({})", ui::path(rel.display()), ui::state(state));
        let vars = envfile::parse(&bytes)?;
        if vars.is_empty() {
            ui::detail("(empty)");
        } else {
            let width = vars.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
            for (key, value) in vars {
                let pad = " ".repeat(width.saturating_sub(key.len()));
                if reveal {
                    println!("  {}{pad} {} {value}", ui::var(&key), ui::dim("="));
                } else {
                    println!(
                        "  {}{pad} {} {}",
                        ui::var(&key),
                        ui::dim("="),
                        ui::dim(mask(&value))
                    );
                }
            }
        }
    }
    if !reveal {
        println!();
        ui::hint(format!(
            "Values are masked; pass {} to print them.",
            ui::strong("--reveal")
        ));
    }
    Ok(())
}

/// Below this length, showing any characters gives away too much of the
/// value, so it is masked entirely.
const MASK_HINT_MIN_LEN: usize = 10;

fn mask(value: &str) -> String {
    let count = value.chars().count();
    if count < MASK_HINT_MIN_LEN {
        return "••••".to_string();
    }
    let first: String = value.chars().take(2).collect();
    let last: String = value.chars().skip(count - 2).collect();
    format!("{first}{}{last}", "•".repeat((count - 4).min(12)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_values() {
        assert_eq!(mask("abc"), "••••");
        // short secrets are fully masked: a prefix/suffix hint would reveal
        // most of the value
        assert_eq!(mask("hunter2"), "••••");
        assert_eq!(mask("secretpw9"), "••••");
        assert_eq!(mask("sk_test_abc123"), "sk••••••••••23");
        // long values don't leak their exact length
        assert_eq!(mask(&"x".repeat(100)), format!("xx{}xx", "•".repeat(12)));
    }
}
