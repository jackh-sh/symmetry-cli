mod decrypt;
mod encrypt;
mod init;
mod key;
mod run;
mod show;
mod status;
mod var;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::cli::{Command, KeyAction};
use crate::crypto::{self, EncFile, KdfParams, KeyMode, SALT_LEN};
use crate::keystore::KeySource;
use crate::manifest::{Manifest, rel_to_root};

pub fn dispatch(command: Command) -> Result<()> {
    match command {
        Command::Init { password, strict, yes } => init::init(password, strict, yes),
        Command::Encrypt { paths, keep } => encrypt::encrypt(paths, keep),
        Command::Decrypt { paths, force } => decrypt::decrypt(paths, force),
        Command::Run { file, all, command } => run::run(file, all, command),
        Command::Status => status::status(),
        Command::Show { path, reveal } => show::show(path, reveal),
        Command::Set { key, value, file } => var::set(&key, &value, file),
        Command::Unset { key, file } => var::unset(&key, file),
        Command::Key { action } => match action {
            KeyAction::Export => key::export(),
            KeyAction::Import { key, strict } => key::import(&key, strict),
            KeyAction::Strict { mode } => key::strict(mode),
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
    Ok(decrypt_entry_full(root, rel, keys)?.0)
}

/// Like `decrypt_entry`, but also reports whether the file was in password
/// mode so it can be re-encrypted the same way.
pub fn decrypt_entry_full(
    root: &Path,
    rel: &Path,
    keys: &mut KeySource,
) -> Result<(Vec<u8>, bool)> {
    let path = enc_path(&root.join(rel));
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let enc = EncFile::parse(&text).with_context(|| format!("in {}", path.display()))?;
    let (key, password_mode) = match enc.mode {
        KeyMode::Keychain => (keys.require_keychain()?, false),
        KeyMode::Password { salt, params } => {
            let password = keys.password(false)?.to_string();
            (crypto::derive_key(&password, &salt, &params)?, true)
        }
    };
    let plaintext =
        crypto::open(&key, &enc, &aad_for(rel)).with_context(|| format!("in {}", path.display()))?;
    Ok((plaintext, password_mode))
}

/// Encrypt `plaintext` to `rel`'s .enc file, keeping the key mode it had.
pub fn seal_entry(
    root: &Path,
    rel: &Path,
    keys: &mut KeySource,
    plaintext: &[u8],
    password_mode: bool,
) -> Result<()> {
    let encfile = if password_mode {
        let password = keys.password(false)?.to_string();
        let salt = crypto::random_bytes::<SALT_LEN>();
        let params = KdfParams::default();
        let key = crypto::derive_key(&password, &salt, &params)?;
        crypto::seal(&key, plaintext, &aad_for(rel), KeyMode::Password { salt, params })?
    } else {
        let key = keys.require_keychain()?;
        crypto::seal(&key, plaintext, &aad_for(rel), KeyMode::Keychain)?
    };
    let path = enc_path(&root.join(rel));
    std::fs::write(&path, encfile.render())
        .with_context(|| format!("failed to write {}", path.display()))
}

/// Resolve which env file a command should act on: an explicit --file, or
/// the one nearest to the current directory.
pub fn resolve_target(root: &Path, manifest: &Manifest, file: Option<PathBuf>) -> Result<PathBuf> {
    match file {
        Some(path) => Ok(strip_enc(rel_to_root(root, &path)?)),
        None => {
            let cwd = std::env::current_dir()?;
            let rel_cwd = cwd.strip_prefix(root).unwrap_or(Path::new("")).to_path_buf();
            nearest(&manifest.paths(), &rel_cwd)
        }
    }
}

/// Pick the env file whose directory most closely contains `rel_cwd`.
/// A single-file manifest always wins; otherwise ambiguity is an error.
pub fn nearest(files: &[PathBuf], rel_cwd: &Path) -> Result<PathBuf> {
    if files.is_empty() {
        bail!("no env files in the manifest");
    }
    if let [only] = files {
        return Ok(only.clone());
    }

    let dir_of = |file: &PathBuf| file.parent().unwrap_or(Path::new("")).to_path_buf();
    let candidates: Vec<&PathBuf> = files
        .iter()
        .filter(|file| rel_cwd.starts_with(dir_of(file)))
        .collect();

    let listing = |files: &[&PathBuf]| {
        files
            .iter()
            .map(|f| format!("  {}", f.display()))
            .collect::<Vec<_>>()
            .join("\n")
    };
    match candidates.as_slice() {
        [] => bail!(
            "no env file matches the current directory; pick one with --file or use --all:\n{}",
            listing(&files.iter().collect::<Vec<_>>())
        ),
        candidates => {
            let deepest = candidates
                .iter()
                .map(|f| dir_of(f).components().count())
                .max()
                .expect("non-empty");
            let winners: Vec<&PathBuf> = candidates
                .iter()
                .filter(|f| dir_of(f).components().count() == deepest)
                .copied()
                .collect();
            match winners.as_slice() {
                [only] => Ok((*only).clone()),
                _ => bail!(
                    "multiple env files match the current directory; pick one with --file:\n{}",
                    listing(&winners)
                ),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(strs: &[&str]) -> Vec<PathBuf> {
        strs.iter().map(PathBuf::from).collect()
    }

    #[test]
    fn single_file_wins_from_anywhere() {
        let files = paths(&["apps/web/.env"]);
        assert_eq!(
            nearest(&files, Path::new("")).unwrap(),
            PathBuf::from("apps/web/.env")
        );
    }

    #[test]
    fn picks_deepest_matching_directory() {
        let files = paths(&[".env", "apps/web/.env", "apps/api/.env"]);
        assert_eq!(
            nearest(&files, Path::new("apps/web")).unwrap(),
            PathBuf::from("apps/web/.env")
        );
        assert_eq!(
            nearest(&files, Path::new("apps/web/src/components")).unwrap(),
            PathBuf::from("apps/web/.env")
        );
        assert_eq!(
            nearest(&files, Path::new("")).unwrap(),
            PathBuf::from(".env")
        );
    }

    #[test]
    fn no_match_is_an_error() {
        let files = paths(&["apps/web/.env", "apps/api/.env"]);
        assert!(nearest(&files, Path::new("docs")).is_err());
    }

    #[test]
    fn same_directory_tie_is_an_error() {
        let files = paths(&["apps/web/.env", "apps/web/.env.local"]);
        assert!(nearest(&files, Path::new("apps/web")).is_err());
    }
}
