//! Files that rpctl owns on the target system.

use std::path::{Component, Path, PathBuf};

/// A file rendered by a module and written verbatim to the target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedFile {
    /// Absolute path on the target system, e.g. `/etc/rp/nftables.nft`.
    pub path: String,
    pub mode: u32,
    pub content: String,
}

impl ManagedFile {
    pub fn new(path: &str, mode: u32, content: String) -> Self {
        assert!(path.starts_with('/'), "managed paths must be absolute: {path}");
        Self { path: path.to_string(), mode, content }
    }
}

/// Header written at the top of every managed text file.
pub const HEADER: &str = "Managed by rpctl — local edits will be overwritten.";

/// Join an absolute target path onto an alternate root (for tests and
/// `--root`). Rejects `..` so a crafted path can't escape the root.
pub fn under_root(root: &Path, target: &str) -> PathBuf {
    let mut out = root.to_path_buf();
    for c in Path::new(target).components() {
        match c {
            Component::Normal(p) => out.push(p),
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir | Component::Prefix(_) => {
                panic!("refusing path with parent component: {target}")
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joins_under_root() {
        assert_eq!(under_root(Path::new("/tmp/r"), "/etc/rp/x"), PathBuf::from("/tmp/r/etc/rp/x"));
        assert_eq!(under_root(Path::new("/"), "/etc/x"), PathBuf::from("/etc/x"));
    }

    #[test]
    #[should_panic(expected = "parent component")]
    fn rejects_escape() {
        under_root(Path::new("/tmp/r"), "/etc/../../x");
    }
}
