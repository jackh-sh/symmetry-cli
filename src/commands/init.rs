use std::path::Path;

use anyhow::{Context, Result, bail};
use zeroize::Zeroize;

use crate::crypto::{self, KEY_LEN};
use crate::keystore;
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

pub fn init(password: bool) -> Result<()> {
    let cwd = std::env::current_dir()?;
    if let Some(existing) = find_root(&cwd) {
        bail!(
            "already initialized: {}",
            existing.join(MANIFEST_NAME).display()
        );
    }

    let files = scan::scan(&cwd)?;
    let manifest = Manifest::new(files.clone());

    if password {
        println!("Password mode: you'll choose a password the first time you encrypt.");
    } else {
        let mut key = crypto::random_bytes::<KEY_LEN>();
        let stored = keystore::store_key(&manifest.project_id, &key);
        key.zeroize();
        match stored {
            Ok(()) => println!("Generated an encryption key and stored it in the system keychain."),
            Err(err) => {
                eprintln!("warning: {err:#}");
                println!("Falling back to password mode: you'll choose a password when encrypting.");
            }
        }
    }

    manifest.save(&cwd)?;
    println!("Wrote {MANIFEST_NAME}");
    update_gitignore(&cwd)?;

    if files.is_empty() {
        println!("No .env files found. Create one and run `symmetry encrypt <path>` to manage it.");
    } else {
        println!("Managing {} env file(s):", files.len());
        for file in &files {
            println!("  {}", file.display());
        }
        println!("Run `symmetry encrypt` to encrypt them.");
    }
    Ok(())
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
    println!("Updated .gitignore ({} stays ignored, *.enc gets committed)", ".env*");
    Ok(())
}
