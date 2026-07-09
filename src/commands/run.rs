use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::commands::{decrypt_entry, enc_path, strip_enc};
use crate::envfile;
use crate::keystore::KeySource;
use crate::manifest::{rel_to_root, require_project};

pub fn run(file: Option<PathBuf>, all: bool, command: Vec<String>) -> Result<()> {
    let (root, manifest) = require_project()?;

    let targets = if let Some(path) = file {
        vec![strip_enc(rel_to_root(&root, &path)?)]
    } else if all {
        let targets = manifest.paths();
        if targets.is_empty() {
            bail!("no env files in the manifest");
        }
        targets
    } else {
        let cwd = std::env::current_dir()?;
        let rel_cwd = cwd.strip_prefix(&root).unwrap_or(Path::new(""));
        vec![nearest(&manifest.paths(), rel_cwd)?]
    };

    let mut keys = KeySource::new(&manifest.project_id);
    let mut vars = Vec::new();
    for rel in &targets {
        let bytes = if enc_path(&root.join(rel)).exists() {
            decrypt_entry(&root, rel, &mut keys)?
        } else {
            let plain = root.join(rel);
            if !plain.exists() {
                bail!("{} has no encrypted or plaintext version", rel.display());
            }
            eprintln!(
                "warning: {} is not encrypted yet, using the plaintext file",
                rel.display()
            );
            std::fs::read(&plain)?
        };
        vars.extend(envfile::parse(&bytes).with_context(|| format!("in {}", rel.display()))?);
    }

    let (program, args) = command
        .split_first()
        .context("missing command; usage: symmetry run -- <cmd> [args...]")?;
    let mut cmd = std::process::Command::new(program);
    cmd.args(args);
    for (name, value) in vars {
        cmd.env(name, value);
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // exec replaces this process, so signals and exit codes flow natively;
        // reaching the next line means it failed.
        Err(cmd.exec()).with_context(|| format!("failed to run {program}"))
    }
    #[cfg(not(unix))]
    {
        let status = cmd
            .status()
            .with_context(|| format!("failed to run {program}"))?;
        std::process::exit(status.code().unwrap_or(1));
    }
}

/// Pick the env file whose directory most closely contains `rel_cwd`.
/// A single-file manifest always wins; otherwise ambiguity is an error.
fn nearest(files: &[PathBuf], rel_cwd: &Path) -> Result<PathBuf> {
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
        assert_eq!(nearest(&files, Path::new("")).unwrap(), PathBuf::from(".env"));
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
