use std::path::PathBuf;

use anyhow::{Context, Result, bail};

use crate::commands::{decrypt_entry, enc_path, resolve_target};
use crate::envfile;
use crate::keystore::KeySource;
use crate::manifest::require_project;
use crate::ui;

pub fn run(file: Option<PathBuf>, all: bool, command: Vec<String>) -> Result<()> {
    let (root, manifest) = require_project()?;

    let targets = if all {
        let targets = manifest.paths();
        if targets.is_empty() {
            bail!("no env files in the manifest");
        }
        targets
    } else {
        vec![resolve_target(&root, &manifest, file)?]
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
            ui::warn(format!(
                "{} is not encrypted yet, using the plaintext file",
                ui::path(rel.display())
            ));
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
