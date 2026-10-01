//! Layout of a pass-compatible password store on disk.

use std::cmp::Ordering;
use std::env;
use std::fs;
use std::path::{Component, Path, PathBuf};

use anyhow::{Result, bail};

use crate::gpg::Gpg;
use crate::term;

pub const EXT: &str = "gpg";
pub const GPG_ID: &str = ".gpg-id";

pub struct Store {
    pub root: PathBuf,
}

impl Store {
    pub fn open() -> Result<Store> {
        let root = match env::var_os("PASSWORD_STORE_DIR") {
            Some(dir) if !dir.is_empty() => PathBuf::from(dir),
            _ => home()?.join(".password-store"),
        };
        Ok(Store { root })
    }

    /// Validates a user-supplied entry name and returns it without leading or
    /// trailing slashes. Like pass, any `..` component is rejected so a name can
    /// never escape the store.
    pub fn clean_name(name: &str) -> Result<String> {
        let trimmed = name.trim_matches('/');
        for c in Path::new(trimmed).components() {
            if !matches!(c, Component::Normal(_) | Component::CurDir) {
                bail!("you've attempted to pass a sneaky path to hidepass. Go home.");
            }
        }
        Ok(trimmed.to_string())
    }

    pub fn entry_path(&self, name: &str) -> PathBuf {
        self.root.join(format!("{name}.{EXT}"))
    }

    pub fn dir_path(&self, name: &str) -> PathBuf {
        if name.is_empty() {
            self.root.clone()
        } else {
            self.root.join(name)
        }
    }

    /// Entry name of a path inside the store (`Email/work` for `<root>/Email/work.gpg`).
    pub fn name_of(&self, path: &Path) -> String {
        let rel = path.strip_prefix(&self.root).unwrap_or(path);
        let s = rel.to_string_lossy();
        s.strip_suffix(&format!(".{EXT}")).unwrap_or(&s).to_string()
    }

    /// The `.gpg-id` file that governs `path`: the nearest one walking up from the
    /// directory containing `path` to the store root.
    pub fn gpg_id_file(&self, path: &Path) -> Result<PathBuf> {
        let mut dir = if path.is_dir() {
            path.to_path_buf()
        } else {
            path.parent().unwrap_or(&self.root).to_path_buf()
        };
        loop {
            let candidate = dir.join(GPG_ID);
            if candidate.is_file() {
                return Ok(candidate);
            }
            if dir == self.root || !dir.starts_with(&self.root) || !dir.pop() {
                bail!(
                    "you must run: hidepass init your-gpg-id before you may use the password store."
                );
            }
        }
    }

    /// GPG recipients for an entry at `path`, honouring `PASSWORD_STORE_KEY` and
    /// verifying `.gpg-id.sig` when `PASSWORD_STORE_SIGNING_KEY` is set.
    pub fn recipients(&self, gpg: &Gpg, path: &Path) -> Result<Vec<String>> {
        if let Ok(keys) = env::var("PASSWORD_STORE_KEY") {
            let keys: Vec<String> = keys.split_whitespace().map(String::from).collect();
            if !keys.is_empty() {
                return Ok(keys);
            }
        }
        let id_file = self.gpg_id_file(path)?;
        verify_gpg_id_signature(gpg, &id_file)?;
        let ids = parse_gpg_ids(&fs::read_to_string(&id_file)?);
        if ids.is_empty() {
            bail!("{} does not contain any GPG id.", id_file.display());
        }
        Ok(ids)
    }

    /// All entry files below `dir`, sorted, skipping hidden files and directories.
    pub fn entries(&self, dir: &Path) -> Result<Vec<PathBuf>> {
        let mut out = Vec::new();
        if dir.is_file() {
            out.push(dir.to_path_buf());
            return Ok(out);
        }
        collect_entries(dir, &mut out)?;
        Ok(out)
    }
}

fn collect_entries(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for (path, is_dir) in sorted_children(dir)? {
        if is_dir {
            collect_entries(&path, out)?;
        } else if is_entry(&path) {
            out.push(path);
        }
    }
    Ok(())
}

pub fn is_entry(path: &Path) -> bool {
    path.extension().is_some_and(|e| e == EXT)
}

/// Visible children of `dir` as `(path, is_dir)`, in tree(1)-like order.
pub fn sorted_children(dir: &Path) -> Result<Vec<(PathBuf, bool)>> {
    let mut children = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        if name.to_string_lossy().starts_with('.') {
            continue;
        }
        let path = entry.path();
        // fs::metadata follows symlinks, like `tree -l` in pass.
        let is_dir = fs::metadata(&path).map(|m| m.is_dir()).unwrap_or(false);
        children.push((path, is_dir));
    }
    children.sort_by(|(a, _), (b, _)| compare_names(a, b));
    Ok(children)
}

fn compare_names(a: &Path, b: &Path) -> Ordering {
    // Byte order, like tree(1) on macOS, so listings match pass.
    a.file_name().cmp(&b.file_name())
}

pub fn parse_gpg_ids(contents: &str) -> Vec<String> {
    contents
        .lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect()
}

fn verify_gpg_id_signature(gpg: &Gpg, id_file: &Path) -> Result<()> {
    let Ok(signing_keys) = env::var("PASSWORD_STORE_SIGNING_KEY") else {
        return Ok(());
    };
    if signing_keys.trim().is_empty() {
        return Ok(());
    }
    let sig = sig_path(id_file);
    if !sig.is_file() {
        bail!("signature for {} does not exist.", id_file.display());
    }
    let signers = gpg.verify_signers(&sig, id_file)?;
    let trusted = signing_keys
        .split_whitespace()
        .filter(|k| {
            k.len() == 40
                && k.chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_lowercase())
        })
        .any(|k| signers.iter().any(|s| s == k));
    if !trusted {
        bail!("signature for {} is invalid.", id_file.display());
    }
    Ok(())
}

pub fn sig_path(id_file: &Path) -> PathBuf {
    let mut s = id_file.as_os_str().to_owned();
    s.push(".sig");
    PathBuf::from(s)
}

/// Removes now-empty parent directories of `path`, stopping at the store root.
pub fn prune_empty_dirs(root: &Path, path: &Path) {
    let mut dir = path.parent();
    while let Some(d) = dir {
        if d == root || !d.starts_with(root) || fs::remove_dir(d).is_err() {
            break;
        }
        dir = d.parent();
    }
}

fn home() -> Result<PathBuf> {
    match env::var_os("HOME") {
        Some(h) if !h.is_empty() => Ok(PathBuf::from(h)),
        _ => bail!("HOME is not set and PASSWORD_STORE_DIR was not given."),
    }
}

/// Prints `dir` as a tree, pass style. `keep` decides which entries (by name
/// without the `.gpg` suffix) are shown; a matching directory shows everything
/// below it, and directories with nothing to show are pruned.
pub fn print_tree(dir: &Path, title: Option<&str>, keep: &dyn Fn(&str) -> bool) -> Result<()> {
    let color = term::stdout_color();
    let mut lines = Vec::new();
    tree_lines(dir, "", keep, false, color, &mut lines)?;
    if let Some(title) = title {
        println!("{title}");
    }
    for line in lines {
        println!("{line}");
    }
    Ok(())
}

fn tree_lines(
    dir: &Path,
    prefix: &str,
    keep: &dyn Fn(&str) -> bool,
    keep_all: bool,
    color: bool,
    out: &mut Vec<String>,
) -> Result<bool> {
    // Build each child's subtree first so pruned children don't affect the
    // `├──`/`└──` choice of their siblings.
    let mut shown: Vec<(String, bool, Vec<String>)> = Vec::new();
    for (path, is_dir) in sorted_children(dir)? {
        let file_name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        if is_dir {
            let all = keep_all || keep(&file_name);
            let mut sub = Vec::new();
            let any = tree_lines(&path, "", keep, all, color, &mut sub)?;
            if any || all {
                shown.push((file_name, true, sub));
            }
        } else if let Some(name) = file_name.strip_suffix(&format!(".{EXT}"))
            && (keep_all || keep(name))
        {
            shown.push((name.to_string(), false, Vec::new()));
        }
    }
    let count = shown.len();
    for (i, (name, is_dir, sub)) in shown.into_iter().enumerate() {
        let last = i + 1 == count;
        let label = if is_dir && color {
            format!("\x1b[01;34m{name}\x1b[0m")
        } else {
            name
        };
        out.push(format!(
            "{prefix}{}{label}",
            if last { "└── " } else { "├── " }
        ));
        let child_prefix = format!("{prefix}{}", if last { "    " } else { "│   " });
        out.extend(sub.into_iter().map(|l| format!("{child_prefix}{l}")));
    }
    Ok(count > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_sneaky_paths() {
        assert!(Store::clean_name("../etc/passwd").is_err());
        assert!(Store::clean_name("a/../../b").is_err());
        assert!(Store::clean_name("a/..").is_err());
        assert_eq!(Store::clean_name("/Email/work/").unwrap(), "Email/work");
        assert_eq!(Store::clean_name("a..b").unwrap(), "a..b");
    }

    #[test]
    fn parses_gpg_ids_with_comments() {
        let ids = parse_gpg_ids("ABC # main key\n\n  # comment\n def@example.com \n");
        assert_eq!(ids, vec!["ABC", "def@example.com"]);
    }
}
