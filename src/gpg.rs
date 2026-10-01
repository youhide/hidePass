//! Thin wrapper around the gpg binary, so the user's agent, pinentry, smartcards
//! and keyring work exactly as they do with pass.

use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use zeroize::Zeroizing;

pub struct Gpg {
    bin: String,
    opts: Vec<String>,
}

impl Gpg {
    pub fn new() -> Gpg {
        // Same binary and option choice as pass.
        let bin = if crate::term::in_path("gpg2") {
            "gpg2"
        } else {
            "gpg"
        }
        .to_string();
        let mut opts: Vec<String> = env::var("PASSWORD_STORE_GPG_OPTS")
            .map(|o| o.split_whitespace().map(String::from).collect())
            .unwrap_or_default();
        opts.extend(
            [
                "--quiet",
                "--yes",
                "--compress-algo=none",
                "--no-encrypt-to",
            ]
            .map(String::from),
        );
        if env::var_os("GPG_AGENT_INFO").is_some() || bin == "gpg2" {
            opts.extend(["--batch", "--use-agent"].map(String::from));
        }
        Gpg { bin, opts }
    }

    /// Command line git uses as `diff.gpg.textconv`, as set by `pass git init`.
    pub fn textconv(&self) -> String {
        format!("{} -d {}", self.bin, self.opts.join(" "))
    }

    fn cmd(&self) -> Command {
        let mut c = Command::new(&self.bin);
        c.args(&self.opts);
        c
    }

    pub fn decrypt(&self, path: &Path) -> Result<Zeroizing<Vec<u8>>> {
        let mut child = self
            .cmd()
            .arg("--decrypt")
            .arg(path)
            .stdin(Stdio::inherit())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .with_context(|| format!("could not run {}", self.bin))?;
        let mut out = Zeroizing::new(Vec::new());
        child.stdout.take().expect("piped").read_to_end(&mut out)?;
        let status = child.wait()?;
        if !status.success() {
            bail!("gpg could not decrypt {}.", path.display());
        }
        Ok(out)
    }

    /// Encrypts `plaintext` to `recipients` into `out`. gpg writes a temporary file
    /// next to `out` that is renamed into place, so an interrupted run never leaves
    /// a truncated entry behind.
    pub fn encrypt(&self, plaintext: &[u8], recipients: &[String], out: &Path) -> Result<()> {
        let dir = out.parent().context("entry has no parent directory")?;
        fs::create_dir_all(dir)?;
        let tmp = temp_sibling(out);
        let mut cmd = self.cmd();
        cmd.arg("--encrypt");
        for r in recipients {
            cmd.arg("-r").arg(r);
        }
        let mut child = cmd
            .arg("-o")
            .arg(&tmp)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .with_context(|| format!("could not run {}", self.bin))?;
        let write = child.stdin.take().expect("piped").write_all(plaintext);
        let status = child.wait()?;
        if write.is_err() || !status.success() {
            let _ = fs::remove_file(&tmp);
            bail!("gpg could not encrypt {}.", out.display());
        }
        fs::rename(&tmp, out).inspect_err(|_| {
            let _ = fs::remove_file(&tmp);
        })?;
        Ok(())
    }

    /// Key ids an entry is currently encrypted to. Needs no secret key.
    pub fn encrypted_to(&self, path: &Path) -> Result<BTreeSet<String>> {
        let out = Command::new(&self.bin)
            .args([
                "--batch",
                "--quiet",
                "--no-secmem-warning",
                "--list-only",
                "--status-fd",
                "1",
                "--decrypt",
            ])
            .arg(path)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .with_context(|| format!("could not run {}", self.bin))?;
        Ok(String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| l.strip_prefix("[GNUPG:] ENC_TO "))
            .filter_map(|l| l.split_whitespace().next())
            .map(|id| id.to_uppercase())
            .collect())
    }

    /// Long key ids of the usable encryption (sub)keys of `recipients`.
    pub fn encryption_key_ids(&self, recipients: &[String]) -> Result<BTreeSet<String>> {
        let out = Command::new(&self.bin)
            .args([
                "--batch",
                "--no-secmem-warning",
                "--with-colons",
                "--list-keys",
                "--",
            ])
            .args(recipients)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .with_context(|| format!("could not run {}", self.bin))?;
        if !out.status.success() {
            bail!(
                "gpg could not find public keys for: {}",
                recipients.join(", ")
            );
        }
        let ids: BTreeSet<String> = String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(|l| l.split(':').collect::<Vec<_>>())
            .filter(|f| f.len() > 11 && (f[0] == "pub" || f[0] == "sub"))
            // Skip invalid, disabled, revoked and expired keys; keep keys whose
            // own capability field allows encryption.
            .filter(|f| !matches!(f[1], "i" | "d" | "r" | "e") && f[11].contains('e'))
            .map(|f| f[4].to_uppercase())
            .collect();
        if ids.is_empty() {
            bail!("no usable encryption key for: {}", recipients.join(", "));
        }
        Ok(ids)
    }

    /// Fingerprints (signing key and primary key) of valid signatures on `file`.
    pub fn verify_signers(&self, sig: &Path, file: &Path) -> Result<Vec<String>> {
        let out = self
            .cmd()
            .args(["--verify", "--status-fd", "1"])
            .arg(sig)
            .arg(file)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .with_context(|| format!("could not run {}", self.bin))?;
        Ok(String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| l.strip_prefix("[GNUPG:] VALIDSIG "))
            .flat_map(|l| {
                let f: Vec<&str> = l.split_whitespace().collect();
                [f.first().copied(), f.last().copied()]
            })
            .flatten()
            .map(String::from)
            .collect())
    }

    pub fn sign_detached(&self, file: &Path, signing_keys: &[String]) -> Result<()> {
        let mut cmd = self.cmd();
        for k in signing_keys {
            cmd.arg("--default-key").arg(k);
        }
        let status = cmd
            .arg("--detach-sign")
            .arg(file)
            .stdin(Stdio::inherit())
            .status()
            .with_context(|| format!("could not run {}", self.bin))?;
        if !status.success() {
            bail!("could not sign {}.", file.display());
        }
        Ok(())
    }
}

fn temp_sibling(path: &Path) -> PathBuf {
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    path.with_file_name(format!(".{name}.tmp-{}", std::process::id()))
}
