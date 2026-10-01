//! Git integration, matching the commits pass makes so both tools can share a
//! repository history.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use anyhow::{Context, Result, bail};

pub struct Git {
    dir: PathBuf,
}

impl Git {
    /// Returns a handle when the store is inside a git work tree.
    pub fn detect(store_root: &Path) -> Option<Git> {
        let inside = Command::new("git")
            .arg("-C")
            .arg(store_root)
            .args(["rev-parse", "--is-inside-work-tree"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        inside.then(|| Git {
            dir: store_root.to_path_buf(),
        })
    }

    fn git(&self) -> Command {
        let mut c = Command::new("git");
        c.arg("-C").arg(&self.dir);
        c
    }

    fn run(&self, args: &[&str], paths: &[&Path]) -> Result<ExitStatus> {
        self.git()
            .args(args)
            .arg("--")
            .args(paths)
            .status()
            .context("could not run git")
    }

    /// Stages `paths` (additions, changes and deletions) and commits if anything
    /// changed.
    pub fn commit(&self, paths: &[&Path], message: &str) -> Result<()> {
        for path in paths {
            if path.exists() {
                self.run(&["add", "-A"], &[path])?;
            } else {
                self.run(&["rm", "-r", "-q", "--cached", "--ignore-unmatch"], &[path])?;
            }
        }
        let staged = self
            .git()
            .args(["diff", "--cached", "--quiet"])
            .status()
            .context("could not run git")?;
        if staged.success() {
            return Ok(());
        }
        let mut commit = self.git();
        commit.arg("commit");
        if self.sign_commits() {
            commit.arg("-S");
        }
        if !commit
            .args(["-m", message])
            .status()
            .context("could not run git")?
            .success()
        {
            bail!("git commit failed.");
        }
        Ok(())
    }

    fn sign_commits(&self) -> bool {
        self.git()
            .args(["config", "--bool", "--get", "pass.signcommits"])
            .output()
            .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).trim() == "true")
    }
}

/// `hidepass git init`: same bootstrap as `pass git init`, including the gpg
/// textconv so `git diff` / `git log -p` show decrypted changes.
pub fn init(store_root: &Path, args: &[String], gpg_textconv: &str) -> Result<()> {
    std::fs::create_dir_all(store_root)?;
    let status = Command::new("git")
        .arg("-C")
        .arg(store_root)
        .args(args)
        .status()?;
    if !status.success() {
        bail!("git init failed.");
    }
    let git = Git {
        dir: store_root.to_path_buf(),
    };
    git.commit(&[store_root], "Add current contents of password store.")?;
    let attributes = store_root.join(".gitattributes");
    std::fs::write(&attributes, "*.gpg diff=gpg\n")?;
    git.commit(
        &[&attributes],
        "Configure git repository for gpg file diff.",
    )?;
    for (key, value) in [
        ("diff.gpg.binary", "true"),
        ("diff.gpg.textconv", gpg_textconv),
    ] {
        git.git().args(["config", "--local", key, value]).status()?;
    }
    Ok(())
}
