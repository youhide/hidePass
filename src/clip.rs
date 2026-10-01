//! Clipboard copy with automatic restore of the previous contents, like pass:
//! a detached `hidepass __clip-restore` process waits out the timeout and puts
//! back whatever was there before, unless the user copied something else.

use std::env;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::term::in_path;

struct Backend {
    copy: Vec<String>,
    paste: Vec<String>,
}

fn backend() -> Result<Backend> {
    let v = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    // Custom clipboards (tmux, OSC 52 over SSH, ...): shell commands that read
    // the data on stdin / print it on stdout.
    if let (Ok(copy), Ok(paste)) = (
        env::var("HIDEPASS_CLIP_COPY"),
        env::var("HIDEPASS_CLIP_PASTE"),
    ) {
        return Ok(Backend {
            copy: v(&["sh", "-c", &copy]),
            paste: v(&["sh", "-c", &paste]),
        });
    }
    if cfg!(target_os = "macos") {
        return Ok(Backend {
            copy: v(&["pbcopy"]),
            paste: v(&["pbpaste"]),
        });
    }
    if env::var_os("WAYLAND_DISPLAY").is_some() && in_path("wl-copy") {
        let mut copy = v(&["wl-copy"]);
        let mut paste = v(&["wl-paste", "-n"]);
        if env::var("PASSWORD_STORE_X_SELECTION").is_ok_and(|s| s == "primary") {
            copy.push("--primary".into());
            paste.push("--primary".into());
        }
        return Ok(Backend { copy, paste });
    }
    if env::var_os("DISPLAY").is_some() && in_path("xclip") {
        let sel = env::var("PASSWORD_STORE_X_SELECTION").unwrap_or_else(|_| "clipboard".into());
        return Ok(Backend {
            copy: v(&["xclip", "-selection", &sel]),
            paste: v(&["xclip", "-o", "-selection", &sel]),
        });
    }
    bail!(
        "no clipboard available (need pbcopy, wl-copy with $WAYLAND_DISPLAY, or xclip with $DISPLAY)."
    )
}

fn set(b: &Backend, data: &[u8]) -> Result<()> {
    let mut child = Command::new(&b.copy[0])
        .args(&b.copy[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("could not run {}", b.copy[0]))?;
    child.stdin.take().expect("piped").write_all(data)?;
    if !child.wait()?.success() {
        bail!("{} failed.", b.copy[0]);
    }
    Ok(())
}

fn get(b: &Backend) -> Zeroizing<Vec<u8>> {
    let out = Command::new(&b.paste[0])
        .args(&b.paste[1..])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output();
    Zeroizing::new(out.map(|o| o.stdout).unwrap_or_default())
}

pub fn clip_time() -> u64 {
    env::var("PASSWORD_STORE_CLIP_TIME")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(45)
}

fn pid_file() -> PathBuf {
    // SAFETY: getuid has no preconditions.
    let uid = unsafe { libc::getuid() };
    env::temp_dir().join(format!("hidepass-clip-{uid}.pid"))
}

/// Makes a pending restorer from an earlier copy finish now, so it puts back the
/// original clipboard before we read it as our own "previous" contents.
fn finish_previous_restorer() {
    let Ok(pid) = fs::read_to_string(pid_file()) else {
        return;
    };
    let Ok(pid) = pid.trim().parse::<libc::pid_t>() else {
        return;
    };
    let is_ours = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "command="])
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("__clip-restore"));
    if !is_ours {
        return;
    }
    // SAFETY: plain syscalls on a pid we just checked.
    unsafe { libc::kill(pid, libc::SIGTERM) };
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline && unsafe { libc::kill(pid, 0) } == 0 {
        thread::sleep(Duration::from_millis(20));
    }
}

pub fn copy(secret: &[u8], what: &str) -> Result<()> {
    let b = backend()?;
    finish_previous_restorer();
    let before = get(&b);
    set(&b, secret)?;

    let timeout = clip_time();
    let exe = env::current_exe()?;
    let mut cmd = Command::new(exe);
    cmd.args(["__clip-restore", &timeout.to_string()])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: setsid is async-signal-safe; detaches the restorer from our
    // terminal so it outlives this process and ignores ^C.
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let mut child = cmd
        .spawn()
        .context("could not start the clipboard restorer")?;
    let mut stdin = child.stdin.take().expect("piped");
    stdin.write_all(&Sha256::digest(secret))?;
    stdin.write_all(&before)?;
    drop(stdin);
    let _ = fs::write(pid_file(), child.id().to_string());

    println!("Copied {what} to clipboard. Will clear in {timeout} seconds.");
    Ok(())
}

/// Body of the detached `__clip-restore` process.
pub fn restore(timeout: u64) -> Result<()> {
    let mut input = Zeroizing::new(Vec::new());
    std::io::stdin().read_to_end(&mut input)?;
    if input.len() < 32 {
        bail!("bad restorer input");
    }
    let (hash, before) = input.split_at(32);

    let stop = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&stop))?;
    let deadline = Instant::now() + Duration::from_secs(timeout);
    while Instant::now() < deadline && !stop.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_millis(100));
    }

    let b = backend()?;
    let now = get(&b);
    // Only restore if the clipboard still holds our secret.
    if Sha256::digest(&*now).as_slice() == hash {
        set(&b, before)?;
    }
    if fs::read_to_string(pid_file()).is_ok_and(|p| p.trim() == std::process::id().to_string()) {
        let _ = fs::remove_file(pid_file());
    }
    Ok(())
}
