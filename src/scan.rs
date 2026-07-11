use std::path::{Path, PathBuf};

use anyhow::Result;
use walkdir::WalkDir;

/// Directories that never contain env files worth managing.
const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "dist",
    "build",
    "out",
    "vendor",
    ".venv",
    "venv",
    "__pycache__",
    ".next",
    ".nuxt",
    ".cache",
    ".turbo",
    ".output",
];

/// Env files that are templates, not secrets.
const SKIP_FILES: &[&str] = &[".env.example", ".env.sample", ".env.template"];

pub fn is_env_file(name: &str) -> bool {
    if name.ends_with(".enc") || SKIP_FILES.contains(&name) {
        return false;
    }
    name == ".env" || name.starts_with(".env.")
}

/// Find all env files under `root`, returned as sorted root-relative paths.
pub fn scan(root: &Path) -> Result<Vec<PathBuf>> {
    let mut found = Vec::new();
    let walker = WalkDir::new(root).into_iter().filter_entry(|entry| {
        !(entry.file_type().is_dir()
            && entry
                .file_name()
                .to_str()
                .is_some_and(|name| SKIP_DIRS.contains(&name)))
    });
    for entry in walker {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        let Some(name) = entry.file_name().to_str() else {
            continue;
        };
        if is_env_file(name) {
            found.push(entry.path().strip_prefix(root)?.to_path_buf());
        }
    }
    found.sort();
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_env_files() {
        assert!(is_env_file(".env"));
        assert!(is_env_file(".env.local"));
        assert!(is_env_file(".env.production"));
        assert!(!is_env_file(".env.enc"));
        assert!(!is_env_file(".env.local.enc"));
        assert!(!is_env_file(".env.example"));
        assert!(!is_env_file(".env.sample"));
        assert!(!is_env_file(".env.template"));
        assert!(!is_env_file("env"));
        assert!(!is_env_file("my.env"));
    }

    #[test]
    fn scans_nested_and_prunes_skip_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        for dir in ["apps/web", "apps/api", "node_modules/pkg"] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        for file in [
            ".env",
            "apps/web/.env",
            "apps/api/.env.production",
            "apps/web/.env.example",
            "node_modules/pkg/.env",
        ] {
            std::fs::write(root.join(file), "A=1\n").unwrap();
        }

        let found = scan(root).unwrap();
        assert_eq!(
            found,
            vec![
                PathBuf::from(".env"),
                PathBuf::from("apps/api/.env.production"),
                PathBuf::from("apps/web/.env"),
            ]
        );
    }
}
