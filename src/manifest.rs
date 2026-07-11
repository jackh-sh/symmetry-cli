use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};

pub const MANIFEST_NAME: &str = "symmetry.toml";

#[derive(Serialize, Deserialize, Clone)]
pub struct Manifest {
    pub version: u32,
    pub project_id: String,
    /// Terminal color: "auto" (default), "always", or "never" (boring mode).
    #[serde(default)]
    pub color: ColorChoice,
    #[serde(default)]
    pub files: Vec<FileEntry>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Default, PartialEq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum ColorChoice {
    /// Color when the terminal supports it, plain when piped.
    #[default]
    Auto,
    /// Always emit color codes.
    Always,
    /// Never emit color codes (boring mode).
    Never,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct FileEntry {
    pub path: PathBuf,
}

impl Manifest {
    pub fn new(files: Vec<PathBuf>) -> Self {
        Manifest {
            version: 1,
            project_id: uuid::Uuid::new_v4().to_string(),
            color: ColorChoice::default(),
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
        crate::fsutil::write_atomic(&path, text.as_bytes(), false)
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

/// The project as located from the current directory, resolved once per
/// invocation (startup color configuration and the command itself share it).
enum Project {
    Found(PathBuf, Manifest),
    Missing,
    Invalid(String),
}

static PROJECT: OnceLock<Project> = OnceLock::new();

fn project() -> &'static Project {
    PROJECT.get_or_init(|| {
        let Ok(cwd) = std::env::current_dir() else {
            return Project::Missing;
        };
        let Some(root) = find_root(&cwd) else {
            return Project::Missing;
        };
        match Manifest::load(&root) {
            Ok(manifest) => Project::Found(root, manifest),
            Err(err) => Project::Invalid(format!("{err:#}")),
        }
    })
}

/// The color preference from the nearest manifest, or Auto if there's no
/// manifest or it can't be read.
pub fn color_choice_from_cwd() -> ColorChoice {
    match project() {
        Project::Found(_, manifest) => manifest.color,
        _ => ColorChoice::default(),
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
    match project() {
        Project::Found(root, manifest) => Ok((root.clone(), manifest.clone())),
        Project::Missing => bail!(
            "no {MANIFEST_NAME} found in this or any parent directory; run `symmetry init` first"
        ),
        Project::Invalid(msg) => bail!("{msg}"),
    }
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
