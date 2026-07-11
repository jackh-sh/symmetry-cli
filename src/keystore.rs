use std::collections::HashMap;

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use zeroize::{Zeroize, Zeroizing};

use crate::auth;
use crate::crypto::{self, KEY_LEN, KdfParams, KeyMode, SALT_LEN};

const SERVICE: &str = "symmetry";
pub const PASSWORD_ENV: &str = "SYMMETRY_PASSWORD";

/// Floor for newly chosen passwords. Existing passwords (decrypting, or
/// supplied via $SYMMETRY_PASSWORD) are accepted as-is.
const MIN_PASSWORD_LEN: usize = 8;

/// Strict-mode keys demand OS user verification (Touch ID / Windows Hello /
/// polkit) before each use. The marker lives inside the keychain payload —
/// not in symmetry.toml — so it can't be switched off by editing a file.
const STRICT_PREFIX: &str = "strict:";

/// Deliberately not `Copy`: copies of key material would escape the
/// zeroize-on-drop below.
#[derive(Clone, PartialEq, Debug)]
pub struct StoredKey {
    pub key: [u8; KEY_LEN],
    pub strict: bool,
}

impl Drop for StoredKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

fn encode_payload(key: &[u8; KEY_LEN], strict: bool) -> Zeroizing<String> {
    let encoded = B64.encode(key);
    Zeroizing::new(if strict {
        format!("{STRICT_PREFIX}{encoded}")
    } else {
        encoded
    })
}

fn decode_payload(payload: &str) -> Result<StoredKey> {
    let (strict, encoded) = match payload.strip_prefix(STRICT_PREFIX) {
        Some(rest) => (true, rest),
        None => (false, payload),
    };
    let mut bytes = B64
        .decode(encoded)
        .context("keychain entry is not valid base64")?;
    let key = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("keychain entry has the wrong key length"));
    bytes.zeroize();
    Ok(StoredKey { key: key?, strict })
}

fn entry(project_id: &str) -> Result<keyring::Entry> {
    keyring::Entry::new(SERVICE, project_id).context("cannot access the system keychain")
}

pub fn store_key(project_id: &str, key: &[u8; KEY_LEN], strict: bool) -> Result<()> {
    entry(project_id)?
        .set_password(&encode_payload(key, strict))
        .context("failed to store the key in the system keychain")
}

/// Load the project key without any strict-mode gating (callers that hand
/// key material to crypto must go through KeySource instead). Ok(None)
/// means the keychain works but holds no key for this project; Err means
/// the keychain itself is unavailable.
pub fn load_key(project_id: &str) -> Result<Option<StoredKey>> {
    match entry(project_id)?.get_password() {
        Ok(payload) => {
            let payload = Zeroizing::new(payload);
            Ok(Some(decode_payload(&payload)?))
        }
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(err) => Err(err).context("failed to read the key from the system keychain"),
    }
}

/// Caches key material so multi-file operations prompt/hit the keychain
/// once, and enforces strict-mode user verification before key release.
pub struct KeySource {
    project_id: String,
    keychain: Option<Result<Option<StoredKey>, String>>,
    verified: bool,
    password: Option<Zeroizing<String>>,
    /// Password-derived keys by salt, so a batch of files sharing a salt
    /// runs Argon2 once instead of once per file.
    derived: HashMap<[u8; SALT_LEN], Zeroizing<[u8; KEY_LEN]>>,
    /// Salt and params for newly encrypted files, generated once per
    /// invocation (reuse across a batch is fine: files still get unique
    /// nonces, and one password would derive the same key anyway).
    fresh: Option<([u8; SALT_LEN], KdfParams)>,
}

impl KeySource {
    pub fn new(project_id: &str) -> Self {
        KeySource {
            project_id: project_id.to_string(),
            keychain: None,
            verified: false,
            password: None,
            derived: HashMap::new(),
            fresh: None,
        }
    }

    fn load(&mut self) -> Result<Option<StoredKey>> {
        // anyhow::Error isn't Clone, so cache the rendered message.
        let cached = self
            .keychain
            .get_or_insert_with(|| load_key(&self.project_id).map_err(|err| format!("{err:#}")));
        match cached {
            Ok(stored) => Ok(stored.clone()),
            Err(msg) => bail!("{msg}"),
        }
    }

    /// Whether the keychain itself failed (as opposed to holding no key).
    pub fn keychain_errored(&self) -> bool {
        matches!(self.keychain, Some(Err(_)))
    }

    /// The keychain key, None if the keychain works but holds no key for
    /// this project, or Err if the keychain is unavailable. Strict keys
    /// require passing OS user verification, once per invocation.
    pub fn try_keychain(&mut self) -> Result<Option<Zeroizing<[u8; KEY_LEN]>>> {
        let Some(stored) = self.load()? else {
            return Ok(None);
        };
        if stored.strict && !self.verified {
            auth::verify_user("unlock this project's env encryption key")?;
            self.verified = true;
        }
        Ok(Some(Zeroizing::new(stored.key)))
    }

    pub fn require_keychain(&mut self) -> Result<Zeroizing<[u8; KEY_LEN]>> {
        self.try_keychain()?.context(
            "no key for this project in the system keychain; import one with \
             `symmetry key import <key>` (from `symmetry key export` on a machine that has it)",
        )
    }

    /// The key for an existing password-mode file; each distinct salt
    /// derives at most once per invocation.
    pub fn password_key(
        &mut self,
        salt: &[u8; SALT_LEN],
        params: &KdfParams,
    ) -> Result<Zeroizing<[u8; KEY_LEN]>> {
        if let Some(key) = self.derived.get(salt) {
            return Ok(key.clone());
        }
        self.ensure_password(false)?;
        let password = self.password.as_ref().map(|p| p.as_str()).expect("just set");
        let key = crypto::derive_key(password, salt, params)?;
        self.derived.insert(*salt, key.clone());
        Ok(key)
    }

    /// Key mode and key for newly encrypted files, confirming the password
    /// on first use. One salt is generated per invocation so encrypting a
    /// batch of files derives the key once.
    pub fn new_password_key(&mut self) -> Result<(KeyMode, Zeroizing<[u8; KEY_LEN]>)> {
        let (salt, params) = match self.fresh {
            Some(pair) => pair,
            None => {
                self.ensure_password(true)?;
                let pair = (crypto::random_bytes::<SALT_LEN>(), KdfParams::default());
                self.fresh = Some(pair);
                pair
            }
        };
        let key = self.password_key(&salt, &params)?;
        Ok((KeyMode::Password { salt, params }, key))
    }

    /// The password from $SYMMETRY_PASSWORD or an interactive prompt, cached
    /// across files. `confirm` asks for it twice (use when encrypting).
    fn ensure_password(&mut self, confirm: bool) -> Result<()> {
        if self.password.is_none() {
            if let Ok(pw) = std::env::var(PASSWORD_ENV).map(Zeroizing::new)
                && !pw.is_empty()
            {
                self.password = Some(pw);
            } else {
                let pw = Zeroizing::new(
                    rpassword::prompt_password("Password: ").context(
                        "failed to read password (set SYMMETRY_PASSWORD when non-interactive)",
                    )?,
                );
                if pw.is_empty() {
                    bail!("password must not be empty");
                }
                if confirm {
                    // A new password is being chosen; enforce a floor.
                    if pw.chars().count() < MIN_PASSWORD_LEN {
                        bail!("password must be at least {MIN_PASSWORD_LEN} characters");
                    }
                    let again = Zeroizing::new(rpassword::prompt_password("Confirm password: ")?);
                    if pw != again {
                        bail!("passwords do not match");
                    }
                }
                self.password = Some(pw);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_roundtrips_both_modes() {
        let key = [42u8; KEY_LEN];
        for strict in [false, true] {
            let payload = encode_payload(&key, strict);
            assert_eq!(decode_payload(&payload).unwrap(), StoredKey { key, strict });
        }
    }

    #[test]
    fn legacy_plain_base64_payload_is_not_strict() {
        let key = [7u8; KEY_LEN];
        let stored = decode_payload(&B64.encode(key)).unwrap();
        assert!(!stored.strict);
        assert_eq!(stored.key, key);
    }

    #[test]
    fn payload_rejects_garbage() {
        assert!(decode_payload("not base64!!").is_err());
        assert!(decode_payload("strict:short").is_err());
    }
}
