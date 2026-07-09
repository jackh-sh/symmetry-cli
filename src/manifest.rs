use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};

pub const MANIFEST_NAME: &str = "symmetry.toml";

#[derive(Serialize, Deserialize)]
pub struct Manifest {
    pub version: u32,
    pub project_id: String,
    #[serde(default)]
    pub files: Vec<FileEntry>,
}

#[derive(Serialize, Deserialize)]
pub struct FileEntry {
    pub path: PathBuf,
}

impl Manifest {
    pub fn new(files: Vec<PathBuf>) -> Self {
        Manifest {
            version: 1,
            project_id: uuid::Uuid::new_v4().to_string(),
            files: files
                .into_iter()
                .map(|path| FileEntry { path })
                .collect(),
        }
    }

    pub fn load(root: &Path) -> Result<Self> {
        let path = root.join(MANIFEST_NAME);
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("invalid manifest at {}", path.display()))
    }

    pub fn save(&self, root: &Path) -> Result<()> {
        let path = root.join(MANIFEST_NAME);
        let text = toml::to_string_pretty(self).context("failed to serialize manifest")?;
        std::fs::write(&path, text).with_context(|| format!("failed to write {}", path.display()))
    }

    pub fn contains(&self, rel: &Path) -> bool {
        self.files.iter().any(|f| f.path == rel)
    }

    pub fn add(&mut self, rel: PathBuf) {
        if !self.contains(&rel) {
            self.files.push(FileEntry { path: rel });
        }
    }

    pub fn paths(&self) -> Vec<PathBuf> {
        self.files.iter().map(|f| f.path.clone()).collect()
    }
}

/// Walk up from `start` looking for a directory containing symmetry.toml.
pub fn find_root(start: &Path) -> Option<PathBuf> {
    let mut dir = start;
    loop {
        if dir.join(MANIFEST_NAME).is_file() {
            return Some(dir.to_path_buf());
        }
        dir = dir.parent()?;
    }
}

/// Locate the project root from the current directory and load its manifest.
pub fn require_project() -> Result<(PathBuf, Manifest)> {
    let cwd = std::env::current_dir()?;
    let Some(root) = find_root(&cwd) else {
        bail!("no {MANIFEST_NAME} found in this or any parent directory; run `symmetry init` first");
    };
    let manifest = Manifest::load(&root)?;
    Ok((root, manifest))
}

/// Resolve a user-supplied path (relative to cwd or absolute) to a root-relative path.
pub fn rel_to_root(root: &Path, path: &Path) -> Result<PathBuf> {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let abs = normalize(&abs);
    abs.strip_prefix(root)
        .map(Path::to_path_buf)
        .map_err(|_| {
            anyhow!(
                "{} is outside the project root {}",
                path.display(),
                root.display()
            )
        })
}

/// Lexically normalize a path, resolving `.` and `..` without touching the filesystem.
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_through_toml() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = Manifest::new(vec![PathBuf::from(".env"), PathBuf::from("apps/web/.env")]);
        manifest.save(tmp.path()).unwrap();

        let loaded = Manifest::load(tmp.path()).unwrap();
        assert_eq!(loaded.version, 1);
        assert_eq!(loaded.project_id, manifest.project_id);
        assert_eq!(loaded.paths(), manifest.paths());
    }

    #[test]
    fn finds_root_from_nested_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let nested = root.join("apps/web/src");
        std::fs::create_dir_all(&nested).unwrap();
        Manifest::new(vec![]).save(root).unwrap();

        assert_eq!(find_root(&nested).unwrap(), root);
        assert_eq!(find_root(root).unwrap(), root);
    }

    #[test]
    fn normalizes_dot_components() {
        assert_eq!(
            normalize(Path::new("/a/b/../c/./d")),
            PathBuf::from("/a/c/d")
        );
    }
}
