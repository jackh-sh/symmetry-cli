use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use zeroize::{Zeroize, Zeroizing};

use crate::cli::StrictMode;
use crate::crypto::KEY_LEN;
use crate::keystore::{self, KeySource};
use crate::manifest::require_project;
use crate::ui;

pub fn export() -> Result<()> {
    let (_root, manifest) = require_project()?;
    // require_keychain enforces strict-mode verification before release.
    let key = KeySource::new(&manifest.project_id).require_keychain()?;
    ui::warn("this is the project's secret key; share it only over a secure channel");
    // Borrow, not `*key`: dereferencing would copy the key onto the stack
    // outside the zeroizing wrappers.
    #[allow(clippy::needless_borrows_for_generic_args)]
    let encoded = Zeroizing::new(B64.encode(&*key));
    println!("{}", &*encoded);
    Ok(())
}

pub fn import(key: &str, strict: bool) -> Result<()> {
    let (_root, manifest) = require_project()?;
    if strict {
        super::init::require_strict_support()?;
    }
    let mut bytes = B64
        .decode(key.trim())
        .context("key is not valid base64; paste the output of `symmetry key export`")?;
    let key: Result<Zeroizing<[u8; KEY_LEN]>> = bytes
        .as_slice()
        .try_into()
        .map(Zeroizing::new)
        .map_err(|_| anyhow!("key must be {KEY_LEN} bytes, got {}", bytes.len()));
    bytes.zeroize();
    let key = key?;
    keystore::store_key(&manifest.project_id, &key, strict)?;
    if strict {
        ui::ok("Key imported into the system keychain with strict mode on.");
    } else {
        ui::ok("Key imported into the system keychain.");
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
        ui::detail(format!(
            "Strict mode is already {}.",
            if target { "on" } else { "off" }
        ));
        return Ok(());
    }

    // Changing the setting is itself a key use: verification is required to
    // relax it, so malware can't simply switch strict mode off.
    let key = KeySource::new(&manifest.project_id).require_keychain()?;
    keystore::store_key(&manifest.project_id, &key, target)?;
    if target {
        ui::ok("Strict mode on: every key use now requires user verification.");
    } else {
        ui::ok("Strict mode off.");
    }
    Ok(())
}
