mod decrypt;
mod encrypt;
mod init;
mod key;
mod run;
mod status;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::cli::{Command, KeyAction};
use crate::crypto::{self, EncFile, KeyMode};
use crate::keystore::KeySource;

pub fn dispatch(command: Command) -> Result<()> {
    match command {
        Command::Init { password, yes } => init::init(password, yes),
        Command::Encrypt { paths, keep } => encrypt::encrypt(paths, keep),
        Command::Decrypt { paths, force } => decrypt::decrypt(paths, force),
        Command::Run { file, all, command } => run::run(file, all, command),
        Command::Status => status::status(),
        Command::Key { action } => match action {
            KeyAction::Export => key::export(),
            KeyAction::Import { key } => key::import(&key),
        },
    }
}

/// apps/web/.env -> apps/web/.env.enc
pub fn enc_path(plain: &Path) -> PathBuf {
    PathBuf::from(format!("{}.enc", plain.display()))
}

/// Accept either form of a user-supplied path: apps/web/.env.enc -> apps/web/.env
pub fn strip_enc(path: PathBuf) -> PathBuf {
    match path.to_str().and_then(|s| s.strip_suffix(".enc")) {
        Some(stripped) => PathBuf::from(stripped),
        None => path,
    }
}

/// AAD binding a ciphertext to its root-relative location, with stable
/// separators across platforms.
pub fn aad_for(rel: &Path) -> Vec<u8> {
    rel.to_string_lossy().replace('\\', "/").into_bytes()
}

/// Read and decrypt `rel`'s .enc file, resolving the key according to the
/// file header (keychain or password).
pub fn decrypt_entry(root: &Path, rel: &Path, keys: &mut KeySource) -> Result<Vec<u8>> {
    let path = enc_path(&root.join(rel));
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let enc = EncFile::parse(&text).with_context(|| format!("in {}", path.display()))?;
    let key = match enc.mode {
        KeyMode::Keychain => keys.require_keychain()?,
        KeyMode::Password { salt } => {
            let password = keys.password(false)?.to_string();
            crypto::derive_key(&password, &salt)?
        }
    };
    crypto::open(&key, &enc, &aad_for(rel)).with_context(|| format!("in {}", path.display()))
}
