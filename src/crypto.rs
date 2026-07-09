use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use rand::rngs::OsRng;

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const SALT_LEN: usize = 16;

const MAGIC: &str = "SYMMETRY v1";
const WRAP_COLS: usize = 76;

/// How the encryption key is obtained, recorded in the file header so
/// decryption knows what to ask for.
#[derive(Clone, PartialEq, Debug)]
pub enum KeyMode {
    Keychain,
    Password { salt: [u8; SALT_LEN] },
}

pub struct EncFile {
    pub mode: KeyMode,
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    OsRng.fill_bytes(&mut buf);
    buf
}

/// Derive a key from a password with Argon2id.
pub fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; KEY_LEN]> {
    let mut key = [0u8; KEY_LEN];
    argon2::Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("key derivation failed: {e}"))?;
    Ok(key)
}

/// Encrypt `plaintext` with a fresh nonce. `aad` binds the ciphertext to its
/// location so an .enc file can't be silently moved to another path.
pub fn seal(key: &[u8; KEY_LEN], plaintext: &[u8], aad: &[u8], mode: KeyMode) -> Result<EncFile> {
    let nonce = random_bytes::<NONCE_LEN>();
    let cipher = XChaCha20Poly1305::new(key.into());
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow!("encryption failed"))?;
    Ok(EncFile {
        mode,
        nonce,
        ciphertext,
    })
}

pub fn open(key: &[u8; KEY_LEN], enc: &EncFile, aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            XNonce::from_slice(&enc.nonce),
            Payload {
                msg: &enc.ciphertext,
                aad,
            },
        )
        .map_err(|_| anyhow!("decryption failed: wrong key/password, or the file was tampered with or moved"))
}

impl EncFile {
    /// Armored text representation, friendly to git diffs.
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str(MAGIC);
        out.push('\n');
        match &self.mode {
            KeyMode::Keychain => out.push_str("key: keychain\n"),
            KeyMode::Password { salt } => {
                out.push_str("key: password\n");
                out.push_str(&format!("salt: {}\n", B64.encode(salt)));
            }
        }
        out.push_str(&format!("nonce: {}\n\n", B64.encode(self.nonce)));
        let body = B64.encode(&self.ciphertext);
        for chunk in body.as_bytes().chunks(WRAP_COLS) {
            out.push_str(std::str::from_utf8(chunk).expect("base64 is ascii"));
            out.push('\n');
        }
        out
    }

    pub fn parse(text: &str) -> Result<Self> {
        let mut lines = text.lines();
        let magic = lines.next().unwrap_or_default();
        if magic.trim() != MAGIC {
            bail!("not a {MAGIC} encrypted file");
        }

        let mut key_kind = None;
        let mut salt = None;
        let mut nonce = None;
        for line in lines.by_ref() {
            let line = line.trim();
            if line.is_empty() {
                break;
            }
            let (name, value) = line
                .split_once(':')
                .with_context(|| format!("malformed header line: {line}"))?;
            let value = value.trim();
            match name.trim() {
                "key" => key_kind = Some(value.to_string()),
                "salt" => salt = Some(decode_fixed::<SALT_LEN>(value).context("invalid salt")?),
                "nonce" => nonce = Some(decode_fixed::<NONCE_LEN>(value).context("invalid nonce")?),
                // Ignore unknown headers for forward compatibility.
                _ => {}
            }
        }

        let mode = match (key_kind.as_deref(), salt) {
            (Some("keychain"), None) => KeyMode::Keychain,
            (Some("password"), Some(salt)) => KeyMode::Password { salt },
            (Some("password"), None) => bail!("password-encrypted file is missing its salt"),
            (Some(other), _) => bail!("unknown key mode: {other}"),
            (None, _) => bail!("missing key header"),
        };
        let nonce = nonce.context("missing nonce header")?;

        let body: String = lines.flat_map(|l| l.trim().chars()).collect();
        let ciphertext = B64.decode(body).context("invalid ciphertext encoding")?;
        if ciphertext.is_empty() {
            bail!("missing ciphertext");
        }

        Ok(EncFile {
            mode,
            nonce,
            ciphertext,
        })
    }
}

fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N]> {
    let bytes = B64.decode(value)?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("expected {N} bytes, got {}", bytes.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let key = random_bytes::<KEY_LEN>();
        let enc = seal(&key, b"SECRET=hunter2\n", b".env", KeyMode::Keychain).unwrap();
        let plain = open(&key, &enc, b".env").unwrap();
        assert_eq!(plain, b"SECRET=hunter2\n");
    }

    #[test]
    fn wrong_key_fails() {
        let key = random_bytes::<KEY_LEN>();
        let other = random_bytes::<KEY_LEN>();
        let enc = seal(&key, b"SECRET=1", b".env", KeyMode::Keychain).unwrap();
        assert!(open(&other, &enc, b".env").is_err());
    }

    #[test]
    fn wrong_aad_fails() {
        let key = random_bytes::<KEY_LEN>();
        let enc = seal(&key, b"SECRET=1", b"apps/web/.env", KeyMode::Keychain).unwrap();
        assert!(open(&key, &enc, b"apps/api/.env").is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = random_bytes::<KEY_LEN>();
        let mut enc = seal(&key, b"SECRET=1", b".env", KeyMode::Keychain).unwrap();
        enc.ciphertext[0] ^= 1;
        assert!(open(&key, &enc, b".env").is_err());
    }

    #[test]
    fn render_parse_roundtrip_keychain() {
        let key = random_bytes::<KEY_LEN>();
        let enc = seal(&key, &[7u8; 500], b".env", KeyMode::Keychain).unwrap();
        let parsed = EncFile::parse(&enc.render()).unwrap();
        assert_eq!(parsed.mode, KeyMode::Keychain);
        assert_eq!(parsed.nonce, enc.nonce);
        assert_eq!(parsed.ciphertext, enc.ciphertext);
        assert_eq!(open(&key, &parsed, b".env").unwrap(), vec![7u8; 500]);
    }

    #[test]
    fn render_parse_roundtrip_password() {
        let salt = random_bytes::<SALT_LEN>();
        let key = derive_key("correct horse", &salt).unwrap();
        let enc = seal(&key, b"A=1\n", b".env", KeyMode::Password { salt }).unwrap();
        let parsed = EncFile::parse(&enc.render()).unwrap();
        let KeyMode::Password { salt: parsed_salt } = parsed.mode else {
            panic!("expected password mode");
        };
        let key2 = derive_key("correct horse", &parsed_salt).unwrap();
        assert_eq!(open(&key2, &parsed, b".env").unwrap(), b"A=1\n");
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(EncFile::parse("").is_err());
        assert!(EncFile::parse("not a header\n").is_err());
        assert!(EncFile::parse("SYMMETRY v1\nkey: keychain\n\n").is_err());
    }
}
