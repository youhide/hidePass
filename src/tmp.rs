//! A private, RAM-backed scratch directory for `edit`, so decrypted entries never
//! touch the disk: /dev/shm on Linux, a ramdisk built with `diskutil image` on
//! macOS (no deprecated hdiutil).

use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

use crate::term;

pub struct SecureDir {
    dir: Option<tempfile::TempDir>,
    ramdisk: Option<String>,
}

impl SecureDir {
    pub fn new() -> Result<SecureDir> {
        if env::var_os("HIDEPASS_NO_RAMDISK").is_none() {
            if let Some(dir) = shm_dir()? {
                return Ok(SecureDir {
                    dir: Some(dir),
                    ramdisk: None,
                });
            }
            if cfg!(target_os = "macos") {
                let dir = private_tempdir(&env::temp_dir())?;
                match mount_ramdisk(dir.path()) {
                    Ok(dev) => {
                        return Ok(SecureDir {
                            dir: Some(dir),
                            ramdisk: Some(dev),
                        });
                    }
                    Err(e) => eprintln!("Warning: could not create a ramdisk: {e:#}"),
                }
            }
        }
        let dir = private_tempdir(&env::temp_dir())?;
        let question = format!(
            "Your system does not have a RAM-backed temporary directory, so the decrypted \
             entry will be written to {}. Continue?",
            dir.path().display()
        );
        if !term::yesno(&question) {
            bail!("aborted.");
        }
        Ok(SecureDir {
            dir: Some(dir),
            ramdisk: None,
        })
    }

    pub fn path(&self) -> &Path {
        self.dir.as_ref().expect("live").path()
    }
}

impl Drop for SecureDir {
    fn drop(&mut self) {
        let Some(dir) = self.dir.take() else { return };
        wipe_dir(dir.path());
        if let Some(dev) = &self.ramdisk {
            let quiet = |c: &mut Command| c.stdout(Stdio::null()).stderr(Stdio::null()).status();
            let _ = quiet(Command::new("umount").arg(dir.path()));
            let _ = quiet(Command::new("diskutil").args(["quiet", "eject", dev]));
        }
        let _ = dir.close();
    }
}

fn private_tempdir(parent: &Path) -> Result<tempfile::TempDir> {
    // tempfile creates the directory with mode 0700.
    tempfile::Builder::new()
        .prefix("hidepass.")
        .tempdir_in(parent)
        .with_context(|| {
            format!(
                "could not create a temporary directory in {}",
                parent.display()
            )
        })
}

fn shm_dir() -> Result<Option<tempfile::TempDir>> {
    let shm = Path::new("/dev/shm");
    if !cfg!(target_os = "linux") || !shm.is_dir() {
        return Ok(None);
    }
    Ok(private_tempdir(shm).ok())
}

/// Attaches a 16 MiB ramdisk, formats it and mounts it on `mount_point`,
/// returning the device node.
fn mount_ramdisk(mount_point: &Path) -> Result<String> {
    let out = Command::new("diskutil")
        .args(["image", "attach", "--noMount", "ram://32768"])
        .stderr(Stdio::null())
        .output()
        .context("could not run diskutil")?;
    let dev = String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_string();
    if !out.status.success() || !dev.starts_with("/dev/") {
        bail!("diskutil image attach failed");
    }
    let ok = |c: &mut Command| {
        c.stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    };
    let formatted = ok(Command::new("newfs_hfs").args(["-M", "700", &dev]));
    let mounted = formatted
        && ok(Command::new("mount")
            .args(["-t", "hfs", "-o", "noatime", "-o", "nobrowse", &dev])
            .arg(mount_point));
    if !mounted {
        let _ = Command::new("diskutil")
            .args(["quiet", "eject", &dev])
            .status();
        bail!("could not format or mount {dev}");
    }
    Ok(dev)
}

/// Best-effort overwrite of every file before removal (editors leave swap and
/// backup files next to the one they edit).
fn wipe_dir(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path: PathBuf = entry.path();
        match entry.file_type() {
            Ok(t) if t.is_dir() => wipe_dir(&path),
            Ok(t) if t.is_file() => {
                if let Ok(len) = entry.metadata().map(|m| m.len())
                    && let Ok(mut f) = fs::OpenOptions::new().write(true).open(&path)
                {
                    let _ = f.write_all(&vec![0u8; len as usize]);
                    let _ = f.sync_all();
                }
                let _ = fs::remove_file(&path);
            }
            _ => {
                let _ = fs::remove_file(&path);
            }
        }
    }
}
