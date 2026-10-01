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

#[cfg(not(target_os = "macos"))]
use crate::term::in_path;

enum Backend {
    /// External programs that read the data on stdin / print it on stdout.
    Commands {
        copy: Vec<String>,
        paste: Vec<String>,
    },
    /// NSPasteboard, which can mark a secret as concealed.
    #[cfg(target_os = "macos")]
    Native,
}

fn backend() -> Result<Backend> {
    let v = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    // Custom clipboards (tmux, OSC 52 over SSH, ...).
    if let (Ok(copy), Ok(paste)) = (
        env::var("HIDEPASS_CLIP_COPY"),
        env::var("HIDEPASS_CLIP_PASTE"),
    ) {
        return Ok(Backend::Commands {
            copy: v(&["sh", "-c", &copy]),
            paste: v(&["sh", "-c", &paste]),
        });
    }
    #[cfg(target_os = "macos")]
    return Ok(Backend::Native);
    #[cfg(not(target_os = "macos"))]
    {
        if env::var_os("WAYLAND_DISPLAY").is_some() && in_path("wl-copy") {
            let mut copy = v(&["wl-copy"]);
            let mut paste = v(&["wl-paste", "-n"]);
            if env::var("PASSWORD_STORE_X_SELECTION").is_ok_and(|s| s == "primary") {
                copy.push("--primary".into());
                paste.push("--primary".into());
            }
            return Ok(Backend::Commands { copy, paste });
        }
        if env::var_os("DISPLAY").is_some() && in_path("xclip") {
            let sel = env::var("PASSWORD_STORE_X_SELECTION").unwrap_or_else(|_| "clipboard".into());
            return Ok(Backend::Commands {
                copy: v(&["xclip", "-selection", &sel]),
                paste: v(&["xclip", "-o", "-selection", &sel]),
            });
        }
        bail!(
            "no clipboard available (need wl-copy with $WAYLAND_DISPLAY, or xclip with $DISPLAY)."
        )
    }
}

impl Backend {
    /// Writes `data`; a `secret` is flagged so clipboard managers skip it where
    /// the platform supports that.
    fn set(&self, data: &[u8], secret: bool) -> Result<()> {
        match self {
            Backend::Commands { copy, .. } => {
                let _ = secret;
                let mut child = Command::new(&copy[0])
                    .args(&copy[1..])
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .with_context(|| format!("could not run {}", copy[0]))?;
                child.stdin.take().expect("piped").write_all(data)?;
                if !child.wait()?.success() {
                    bail!("{} failed.", copy[0]);
                }
                Ok(())
            }
            #[cfg(target_os = "macos")]
            Backend::Native => mac::set(data, secret),
        }
    }

    fn get(&self) -> Zeroizing<Vec<u8>> {
        match self {
            Backend::Commands { paste, .. } => {
                let out = Command::new(&paste[0])
                    .args(&paste[1..])
                    .stdin(Stdio::null())
                    .stderr(Stdio::null())
                    .output();
                Zeroizing::new(out.map(|o| o.stdout).unwrap_or_default())
            }
            #[cfg(target_os = "macos")]
            Backend::Native => mac::get(),
        }
    }

    /// Distinguishes clipboards so a restorer for one never touches another.
    fn id(&self) -> String {
        let key = match self {
            Backend::Commands { copy, .. } => copy.join(" "),
            #[cfg(target_os = "macos")]
            Backend::Native => mac::board_name(),
        };
        let digest = Sha256::digest(key.as_bytes());
        data_encoding::HEXLOWER.encode(&digest[..6])
    }
}

#[cfg(target_os = "macos")]
mod mac {
    use anyhow::{Context, Result, bail};
    use objc2::rc::Retained;
    use objc2_app_kit::{NSPasteboard, NSPasteboardTypeString};
    use objc2_foundation::NSString;
    use zeroize::Zeroizing;

    /// Marker types from nspasteboard.org that clipboard managers (Maccy,
    /// Raycast, Alfred, Paste, ...) honour: don't show or record this item.
    const SECRET_TYPES: [&str; 2] = [
        "org.nspasteboard.ConcealedType",
        "org.nspasteboard.TransientType",
    ];

    /// The general pasteboard, or a private named one (used by the tests).
    pub fn board_name() -> String {
        std::env::var("HIDEPASS_MACOS_PASTEBOARD").unwrap_or_default()
    }

    fn board() -> Retained<NSPasteboard> {
        match board_name().as_str() {
            "" => NSPasteboard::generalPasteboard(),
            name => NSPasteboard::pasteboardWithName(&NSString::from_str(name)),
        }
    }

    pub fn set(data: &[u8], secret: bool) -> Result<()> {
        let text = std::str::from_utf8(data).context("only text can be put on the clipboard")?;
        let pb = board();
        pb.clearContents();
        if text.is_empty() && !secret {
            return Ok(());
        }
        // SAFETY: reading an immutable AppKit constant.
        let string_type = unsafe { NSPasteboardTypeString };
        if !pb.setString_forType(&NSString::from_str(text), string_type) {
            bail!("could not write to the clipboard.");
        }
        if secret {
            for marker in SECRET_TYPES {
                pb.setString_forType(&NSString::from_str(""), &NSString::from_str(marker));
            }
        }
        Ok(())
    }

    pub fn get() -> Zeroizing<Vec<u8>> {
        // SAFETY: reading an immutable AppKit constant.
        let string_type = unsafe { NSPasteboardTypeString };
        Zeroizing::new(
            board()
                .stringForType(string_type)
                .map(|s| s.to_string().into_bytes())
                .unwrap_or_default(),
        )
    }

    #[cfg(test)]
    pub fn types() -> Vec<String> {
        board()
            .types()
            .map(|t| t.to_vec().iter().map(|s| s.to_string()).collect())
            .unwrap_or_default()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn secrets_are_marked_concealed_and_restores_are_not() {
            let name = format!("hidepass-test-{}", std::process::id());
            // SAFETY: this test is the only code in the process reading this variable.
            unsafe { std::env::set_var("HIDEPASS_MACOS_PASTEBOARD", &name) };

            set(b"s3cret", true).unwrap();
            assert_eq!(&*get(), b"s3cret");
            let t = types();
            assert!(
                SECRET_TYPES.iter().all(|m| t.iter().any(|x| x == m)),
                "{t:?}"
            );

            set(b"plain", false).unwrap();
            assert_eq!(&*get(), b"plain");
            assert!(!types().iter().any(|x| x.starts_with("org.nspasteboard.")));

            set(b"", false).unwrap();
            assert!(get().is_empty());
            // SAFETY: releaseGlobally takes no arguments and returns void.
            unsafe { objc2::msg_send![&*board(), releaseGlobally] }
        }
    }
}

pub fn clip_time() -> u64 {
    env::var("PASSWORD_STORE_CLIP_TIME")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(45)
}

fn pid_file(b: &Backend) -> PathBuf {
    // SAFETY: getuid has no preconditions.
    let uid = unsafe { libc::getuid() };
    env::temp_dir().join(format!("hidepass-clip-{uid}-{}.pid", b.id()))
}

/// Makes a pending restorer from an earlier copy finish now, so it puts back the
/// original clipboard before we read it as our own "previous" contents.
fn finish_previous_restorer(b: &Backend) {
    let Ok(pid) = fs::read_to_string(pid_file(b)) else {
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
    finish_previous_restorer(&b);
    let before = b.get();
    b.set(secret, true)?;

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
    let _ = fs::write(pid_file(&b), child.id().to_string());

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
    let now = b.get();
    // Only restore if the clipboard still holds our secret.
    if Sha256::digest(&*now).as_slice() == hash {
        b.set(before, false)?;
    }
    let pid_file = pid_file(&b);
    if fs::read_to_string(&pid_file).is_ok_and(|p| p.trim() == std::process::id().to_string()) {
        let _ = fs::remove_file(pid_file);
    }
    Ok(())
}
