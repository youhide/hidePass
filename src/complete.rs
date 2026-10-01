//! Dynamic shell completion of entry and folder names. The shell scripts from
//! `hidepass completions <shell>` call back into hidepass (`COMPLETE=<shell>`),
//! so completions always reflect the current store.

use std::ffi::OsStr;
use std::path::Path;

use clap_complete::engine::CompletionCandidate;

use crate::store::{self, Store};

/// Entries and folders one level below the folder typed so far, so the shell
/// walks the store like a directory tree. Folders end with `/`.
pub fn entries(current: &OsStr) -> Vec<CompletionCandidate> {
    level(current, true)
}

/// Folders only, for commands that take a subfolder.
pub fn folders(current: &OsStr) -> Vec<CompletionCandidate> {
    level(current, false)
}

fn level(current: &OsStr, with_entries: bool) -> Vec<CompletionCandidate> {
    let Ok(store) = Store::open() else {
        return Vec::new();
    };
    let current = current.to_string_lossy();
    let parent = current.rfind('/').map(|i| &current[..=i]).unwrap_or("");
    let Ok(clean) = Store::clean_name(parent) else {
        return Vec::new();
    };
    let dir = store.dir_path(&clean);
    let mut out = Vec::new();
    for (path, is_dir) in store::sorted_children(&dir).unwrap_or_default() {
        let name = file_name(&path);
        if is_dir {
            out.push(CompletionCandidate::new(format!("{parent}{name}/")));
        } else if with_entries && let Some(entry) = name.strip_suffix(".gpg") {
            out.push(CompletionCandidate::new(format!("{parent}{entry}")));
        }
    }
    out.retain(|c| {
        c.get_value()
            .to_string_lossy()
            .starts_with(current.as_ref())
    });
    out
}

/// Every entry and folder in the store, for `hidepass <name>` at the top level
/// (the shell filters by what was typed).
pub fn all_entries() -> Vec<CompletionCandidate> {
    let Ok(store) = Store::open() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    walk(&store, &store.root, &mut out);
    out
}

fn walk(store: &Store, dir: &Path, out: &mut Vec<CompletionCandidate>) {
    for (path, is_dir) in store::sorted_children(dir).unwrap_or_default() {
        if is_dir {
            out.push(CompletionCandidate::new(format!(
                "{}/",
                store.name_of(&path)
            )));
            walk(store, &path, out);
        } else if store::is_entry(&path) {
            out.push(CompletionCandidate::new(store.name_of(&path)));
        }
    }
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned()
}
