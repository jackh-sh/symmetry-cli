use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use zeroize::Zeroize;

use crate::crypto::KEY_LEN;

const SERVICE: &str = "symmetry";
pub const PASSWORD_ENV: &str = "SYMMETRY_PASSWORD";

fn entry(project_id: &str) -> Result<keyring::Entry> {
    keyring::Entry::new(SERVICE, project_id).context("cannot access the system keychain")
}

pub fn store_key(project_id: &str, key: &[u8; KEY_LEN]) -> Result<()> {
    entry(project_id)?
        .set_password(&B64.encode(key))
        .context("failed to store the key in the system keychain")
}

/// Load the project key. Ok(None) means the keychain works but holds no key
/// for this project; Err means the keychain itself is unavailable.
pub fn load_key(project_id: &str) -> Result<Option<[u8; KEY_LEN]>> {
    match entry(project_id)?.get_password() {
        Ok(encoded) => {
            let bytes = B64
                .decode(&encoded)
                .context("keychain entry is not valid base64")?;
            let key = bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("keychain entry has the wrong key length"))?;
            Ok(Some(key))
        }
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(err) => Err(err).context("failed to read the key from the system keychain"),
    }
}

/// Caches key material so multi-file operations prompt/hit the keychain once.
pub struct KeySource {
    project_id: String,
    keychain: Option<Option<[u8; KEY_LEN]>>,
    password: Option<String>,
}

impl KeySource {
    pub fn new(project_id: &str) -> Self {
        KeySource {
            project_id: project_id.to_string(),
            keychain: None,
            password: None,
        }
    }

    /// The keychain key, or None if the keychain is empty or unavailable
    /// (unavailability is reported once as a warning).
    pub fn try_keychain(&mut self) -> Option<[u8; KEY_LEN]> {
        if self.keychain.is_none() {
            self.keychain = Some(match load_key(&self.project_id) {
                Ok(key) => key,
                Err(err) => {
                    eprintln!("warning: {err:#}");
                    None
                }
            });
        }
        self.keychain.unwrap()
    }

    pub fn require_keychain(&mut self) -> Result<[u8; KEY_LEN]> {
        self.try_keychain().context(
            "no key for this project in the system keychain; import one with \
             `symmetry key import <key>` (from `symmetry key export` on a machine that has it)",
        )
    }

    /// The password from $SYMMETRY_PASSWORD or an interactive prompt, cached
    /// across files. `confirm` asks for it twice (use when encrypting).
    pub fn password(&mut self, confirm: bool) -> Result<&str> {
        if self.password.is_none() {
            if let Ok(pw) = std::env::var(PASSWORD_ENV)
                && !pw.is_empty()
            {
                self.password = Some(pw);
            } else {
                let pw = rpassword::prompt_password("Password: ")
                    .context("failed to read password (set SYMMETRY_PASSWORD when non-interactive)")?;
                if pw.is_empty() {
                    bail!("password must not be empty");
                }
                if confirm {
                    let again = rpassword::prompt_password("Confirm password: ")?;
                    if pw != again {
                        bail!("passwords do not match");
                    }
                }
                self.password = Some(pw);
            }
        }
        Ok(self.password.as_deref().expect("just set"))
    }
}

impl Drop for KeySource {
    fn drop(&mut self) {
        if let Some(Some(mut key)) = self.keychain.take() {
            key.zeroize();
        }
        if let Some(mut pw) = self.password.take() {
            pw.zeroize();
        }
    }
}
