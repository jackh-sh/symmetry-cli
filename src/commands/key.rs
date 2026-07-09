use anyhow::{Context, Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

use crate::crypto::KEY_LEN;
use crate::keystore::{self, KeySource};
use crate::manifest::require_project;

pub fn export() -> Result<()> {
    let (_root, manifest) = require_project()?;
    let key = KeySource::new(&manifest.project_id).require_keychain()?;
    eprintln!("warning: this is the project's secret key; share it only over a secure channel");
    println!("{}", B64.encode(key));
    Ok(())
}

pub fn import(key: &str) -> Result<()> {
    let (_root, manifest) = require_project()?;
    let bytes = B64
        .decode(key.trim())
        .context("key is not valid base64; paste the output of `symmetry key export`")?;
    let key: [u8; KEY_LEN] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("key must be {KEY_LEN} bytes, got {}", bytes.len()))?;
    keystore::store_key(&manifest.project_id, &key)?;
    println!("Key imported into the system keychain.");
    Ok(())
}
