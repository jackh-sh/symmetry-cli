use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

use crate::cli::StrictMode;
use crate::crypto::KEY_LEN;
use crate::keystore::{self, KeySource};
use crate::manifest::require_project;

pub fn export() -> Result<()> {
    let (_root, manifest) = require_project()?;
    // require_keychain enforces strict-mode verification before release.
    let key = KeySource::new(&manifest.project_id).require_keychain()?;
    eprintln!("warning: this is the project's secret key; share it only over a secure channel");
    println!("{}", B64.encode(key));
    Ok(())
}

pub fn import(key: &str, strict: bool) -> Result<()> {
    let (_root, manifest) = require_project()?;
    if strict {
        super::init::require_strict_support()?;
    }
    let bytes = B64
        .decode(key.trim())
        .context("key is not valid base64; paste the output of `symmetry key export`")?;
    let key: [u8; KEY_LEN] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("key must be {KEY_LEN} bytes, got {}", bytes.len()))?;
    keystore::store_key(&manifest.project_id, &key, strict)?;
    if strict {
        println!("Key imported into the system keychain with strict mode on.");
    } else {
        println!("Key imported into the system keychain.");
    }
    Ok(())
}

pub fn strict(mode: StrictMode) -> Result<()> {
    let (_root, manifest) = require_project()?;
    let target = matches!(mode, StrictMode::On);
    if target {
        super::init::require_strict_support()?;
    }

    let Some(stored) = keystore::load_key(&manifest.project_id)? else {
        bail!("no keychain key for this project; strict mode applies to keychain keys only");
    };
    if stored.strict == target {
        println!("Strict mode is already {}.", if target { "on" } else { "off" });
        return Ok(());
    }

    // Changing the setting is itself a key use: verification is required to
    // relax it, so malware can't simply switch strict mode off.
    let key = KeySource::new(&manifest.project_id).require_keychain()?;
    keystore::store_key(&manifest.project_id, &key, target)?;
    if target {
        println!("Strict mode on: every key use now requires user verification.");
    } else {
        println!("Strict mode off.");
    }
    Ok(())
}
