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
use crate::crypto::{self, EncFile, KeyMode};
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
    let mut name = plain.as_os_str().to_os_string();
    name.push(".enc");
    PathBuf::from(name)
}

/// Accept either form of a user-supplied path: apps/web/.env.enc -> apps/web/.env
pub fn strip_enc(path: PathBuf) -> PathBuf {
    if path.extension().is_some_and(|ext| ext == "enc") {
        path.with_extension("")
    } else {
        path
    }
}

/// AAD binding a ciphertext to its root-relative location, with stable
/// separators across platforms. Rejects non-UTF-8 paths rather than binding
/// to a lossy rendering that another path could alias.
pub fn aad_for(rel: &Path) -> Result<Vec<u8>> {
    let rel = rel
        .to_str()
        .with_context(|| format!("path {} is not valid UTF-8", rel.display()))?;
    Ok(rel.replace('\\', "/").into_bytes())
}

/// Read and decrypt `rel`'s .enc file, resolving the key according to the
/// file header (keychain or password).
pub fn decrypt_entry(root: &Path, rel: &Path, keys: &mut KeySource) -> Result<Vec<u8>> {
    Ok(decrypt_entry_full(root, rel, keys)?.0)
}

/// Like `decrypt_entry`, but also returns the file's key mode so it can be
/// re-encrypted the same way.
pub fn decrypt_entry_full(
    root: &Path,
    rel: &Path,
    keys: &mut KeySource,
) -> Result<(Vec<u8>, KeyMode)> {
    let path = enc_path(&root.join(rel));
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let enc = EncFile::parse(&text).with_context(|| format!("in {}", path.display()))?;
    let key = match &enc.mode {
        KeyMode::Keychain => keys.require_keychain()?,
        KeyMode::Password { salt, params } => keys.password_key(salt, params)?,
    };
    let plaintext = crypto::open(&key, &enc, &aad_for(rel)?)
        .with_context(|| format!("in {}", path.display()))?;
    Ok((plaintext, enc.mode))
}

/// Encrypt `plaintext` to `rel`'s .enc file, keeping the key mode it had.
/// Password mode reuses the file's salt: the same password derives the same
/// key (a cache hit here), and secrecy comes from the fresh nonce.
pub fn seal_entry(
    root: &Path,
    rel: &Path,
    keys: &mut KeySource,
    plaintext: &[u8],
    mode: &KeyMode,
) -> Result<()> {
    let key = match mode {
        KeyMode::Keychain => keys.require_keychain()?,
        KeyMode::Password { salt, params } => keys.password_key(salt, params)?,
    };
    let encfile = crypto::seal(&key, plaintext, &aad_for(rel)?, mode.clone())?;
    let path = enc_path(&root.join(rel));
    crate::fsutil::write_atomic(&path, encfile.render().as_bytes(), false)
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
    fn enc_path_and_strip_enc_roundtrip() {
        assert_eq!(
            enc_path(Path::new("apps/web/.env")),
            PathBuf::from("apps/web/.env.enc")
        );
        assert_eq!(
            strip_enc(PathBuf::from("apps/web/.env.enc")),
            PathBuf::from("apps/web/.env")
        );
        assert_eq!(
            strip_enc(PathBuf::from(".env.local.enc")),
            PathBuf::from(".env.local")
        );
        assert_eq!(strip_enc(PathBuf::from(".env")), PathBuf::from(".env"));
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
