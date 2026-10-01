//! End-to-end tests against a throwaway GNUPGHOME and store. They need gpg and
//! git on PATH, and never touch the real keyring, store or clipboard.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::Duration;

use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
use tempfile::TempDir;

struct Env {
    tmp: TempDir,
}

impl Env {
    fn new() -> Env {
        let tmp = tempfile::Builder::new().prefix("hp").tempdir().unwrap();
        let env = Env { tmp };
        fs::create_dir(env.gnupg()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(env.gnupg(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        env.new_key("Alice <alice@test>");
        env
    }

    fn gnupg(&self) -> PathBuf {
        self.tmp.path().join("g")
    }

    fn store(&self) -> PathBuf {
        self.tmp.path().join("store")
    }

    fn clipboard(&self) -> PathBuf {
        self.tmp.path().join("clipboard")
    }

    fn gpg(&self, args: &[&str]) -> String {
        let out = Command::new("gpg")
            .env("GNUPGHOME", self.gnupg())
            .args(["--batch", "--quiet", "--passphrase", ""])
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "gpg {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    fn new_key(&self, uid: &str) {
        self.gpg(&["--quick-gen-key", uid, "ed25519", "cert,sign", "never"]);
        let fpr = self.fingerprint(uid);
        self.gpg(&["--quick-add-key", &fpr, "cv25519", "encr", "never"]);
    }

    fn fingerprint(&self, uid: &str) -> String {
        let colons = self.gpg(&["--with-colons", "--list-keys", uid]);
        colons
            .lines()
            .find_map(|l| l.strip_prefix("fpr:"))
            .unwrap()
            .trim_matches(':')
            .to_string()
    }

    fn hp(&self) -> assert_cmd::Command {
        let mut cmd = cargo_bin_cmd!("hidepass");
        let clip = self.clipboard();
        cmd.env("GNUPGHOME", self.gnupg())
            .env("PASSWORD_STORE_DIR", self.store())
            .env("HIDEPASS_CLIP_COPY", format!("cat > '{}'", clip.display()))
            .env("HIDEPASS_CLIP_PASTE", format!("cat '{}'", clip.display()))
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@test")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@test")
            .env_remove("PASSWORD_STORE_KEY")
            .env_remove("PASSWORD_STORE_SIGNING_KEY")
            .env_remove("PASSWORD_STORE_GPG_OPTS");
        cmd
    }

    fn init_with_git(&self) {
        self.hp().args(["init", "alice@test"]).assert().success();
        self.hp().args(["git", "init", "-q"]).assert().success();
    }

    fn insert(&self, name: &str, contents: &str) {
        self.hp()
            .args(["insert", "-m", "-f", name])
            .write_stdin(contents)
            .assert()
            .success();
    }

    fn show(&self, name: &str) -> String {
        let out = self.hp().args(["show", name]).output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }

    fn git_log(&self) -> Vec<String> {
        let out = Command::new("git")
            .arg("-C")
            .arg(self.store())
            .args(["log", "--format=%s"])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(String::from)
            .collect()
    }

    fn encrypted_to(&self, entry: &str) -> usize {
        let out = Command::new("gpg")
            .env("GNUPGHOME", self.gnupg())
            .args(["--batch", "--list-only", "--status-fd", "1", "--decrypt"])
            .arg(self.store().join(format!("{entry}.gpg")))
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout)
            .matches("ENC_TO")
            .count()
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = Command::new("gpgconf")
            .env("GNUPGHOME", self.gnupg())
            .args(["--kill", "all"])
            .status();
    }
}

#[test]
fn insert_show_and_tree() {
    let env = Env::new();
    env.init_with_git();
    env.hp()
        .args(["insert", "Email/work"])
        .write_stdin("hunter2\n")
        .assert()
        .success();
    env.insert(
        "Web/github",
        "s3cret\nuser: alice\nurl: https://github.com\n",
    );

    assert_eq!(env.show("Email/work"), "hunter2\n");
    env.hp()
        .arg("Email/work")
        .assert()
        .success()
        .stdout("hunter2\n");
    env.hp()
        .args(["show", "--field", "user", "Web/github"])
        .assert()
        .success()
        .stdout("alice\n");
    env.hp()
        .args(["show", "--field", "password", "Web/github"])
        .assert()
        .success()
        .stdout("s3cret\n");
    env.hp()
        .assert()
        .success()
        .stdout("Password Store\n├── Email\n│   └── work\n└── Web\n    └── github\n");
    env.hp()
        .args(["ls", "Web"])
        .assert()
        .success()
        .stdout("Web\n└── github\n");
    env.hp()
        .args(["show", "Nope"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not in the password store"));
    assert_eq!(
        env.git_log()[..2],
        [
            "Add given password for Web/github to store.",
            "Add given password for Email/work to store."
        ]
    );
}

#[test]
fn rejects_sneaky_paths() {
    let env = Env::new();
    env.init_with_git();
    env.hp()
        .args(["show", "../../etc/passwd"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("sneaky"));
    env.hp()
        .args(["insert", "a/../../x"])
        .write_stdin("x\n")
        .assert()
        .failure();
}

#[test]
fn generate_respects_length_charset_and_in_place() {
    let env = Env::new();
    env.init_with_git();
    env.hp()
        .args(["generate", "-n", "site", "32"])
        .assert()
        .success();
    let pw = env.show("site");
    assert_eq!(pw.trim_end().len(), 32);
    assert!(pw.trim_end().chars().all(|c| c.is_ascii_alphanumeric()));

    env.insert("site", "old\nuser: bob\n");
    env.hp()
        .args(["generate", "-i", "site", "12"])
        .assert()
        .success();
    let contents = env.show("site");
    let lines: Vec<&str> = contents.lines().collect();
    assert_eq!(lines.len(), 2);
    assert_ne!(lines[0], "old");
    assert_eq!(lines[0].len(), 12);
    assert_eq!(lines[1], "user: bob");
    assert_eq!(env.git_log()[0], "Replace generated password for site.");
}

#[test]
fn move_copy_remove_with_reencryption() {
    let env = Env::new();
    env.new_key("Bob <bob@test>");
    env.init_with_git();
    env.insert("a/one", "1\n");
    env.insert("a/two", "2\n");
    env.hp()
        .args(["init", "-p", "shared", "alice@test", "bob@test"])
        .assert()
        .success();

    env.hp().args(["mv", "a/one", "shared/"]).assert().success();
    assert!(!env.store().join("a/one.gpg").exists());
    assert_eq!(env.show("shared/one"), "1\n");
    assert_eq!(env.encrypted_to("shared/one"), 2);
    assert_eq!(env.git_log()[0], "Rename a/one to shared/.");

    env.hp().args(["cp", "a/two", "b/two"]).assert().success();
    assert_eq!(env.show("b/two"), "2\n");
    env.hp()
        .args(["rm", "a"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("-r"));
    env.hp().args(["rm", "-rf", "a"]).assert().success();
    assert!(!env.store().join("a").exists());
    assert_eq!(env.git_log()[0], "Remove a from store.");
    env.hp()
        .arg("check")
        .assert()
        .success()
        .stdout(predicate::str::contains("All 2 entries"));
}

#[test]
fn check_finds_and_fixes_wrong_recipients() {
    let env = Env::new();
    env.new_key("Bob <bob@test>");
    env.init_with_git();
    env.insert("x", "secret\n");
    fs::write(env.store().join(".gpg-id"), "alice@test\nbob@test\n").unwrap();

    env.hp()
        .arg("check")
        .assert()
        .failure()
        .stdout(predicate::str::contains("x: needs re-encryption"));
    env.hp().args(["check", "--fix"]).assert().success();
    assert_eq!(env.encrypted_to("x"), 2);
    env.hp().arg("check").assert().success();
}

#[test]
fn init_refuses_unknown_keys() {
    let env = Env::new();
    env.hp().args(["init", "nobody@test"]).assert().failure();
    assert!(!env.store().join(".gpg-id").exists());
}

#[test]
fn signed_gpg_id_is_enforced() {
    let env = Env::new();
    let fpr = env.fingerprint("alice@test");
    env.hp()
        .env("PASSWORD_STORE_SIGNING_KEY", &fpr)
        .args(["init", "alice@test"])
        .assert()
        .success();
    assert!(env.store().join(".gpg-id.sig").exists());
    env.insert("x", "secret\n");
    env.hp()
        .env("PASSWORD_STORE_SIGNING_KEY", &fpr)
        .args(["show", "x"])
        .assert()
        .success();

    fs::write(env.store().join(".gpg-id"), "alice@test\nmallory@test\n").unwrap();
    env.hp()
        .env("PASSWORD_STORE_SIGNING_KEY", &fpr)
        .args(["insert", "-f", "y"])
        .write_stdin("y\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("is invalid"));
}

#[test]
fn find_and_grep() {
    let env = Env::new();
    env.init_with_git();
    env.insert("Email/work", "pw\nuser: alice\n");
    env.insert("Web/github", "pw\nuser: bob\n");
    env.hp()
        .args(["find", "GIT"])
        .assert()
        .success()
        .stdout("Search Terms: GIT\n└── Web\n    └── github\n");
    env.hp()
        .args(["grep", "-i", "ALICE"])
        .assert()
        .success()
        .stdout("Email/work:\nuser: alice\n");
}

#[test]
fn otp_codes() {
    let env = Env::new();
    env.init_with_git();
    env.insert(
        "totp",
        "pw\notpauth://totp/Ex:me?secret=JBSWY3DPEHPK3PXP&issuer=Ex\n",
    );
    env.hp()
        .args(["otp", "totp"])
        .assert()
        .success()
        .stdout(predicate::str::is_match(r"^\d{6}\n$").unwrap());
    env.hp().args(["otp", "Email"]).assert().failure();
}

#[test]
fn clipboard_is_restored() {
    let env = Env::new();
    env.init_with_git();
    env.insert("x", "first\nsecond\n");
    fs::write(env.clipboard(), "ORIGINAL").unwrap();

    env.hp()
        .env("PASSWORD_STORE_CLIP_TIME", "1")
        .args(["-c2", "x"])
        .assert()
        .success();
    assert_eq!(fs::read_to_string(env.clipboard()).unwrap(), "second");
    thread::sleep(Duration::from_millis(2500));
    assert_eq!(fs::read_to_string(env.clipboard()).unwrap(), "ORIGINAL");
}

#[test]
fn edit_round_trip() {
    let env = Env::new();
    env.init_with_git();
    env.insert("x", "old\n");
    let editor = env.tmp.path().join("ed.sh");
    fs::write(&editor, "#!/bin/sh\nprintf 'new\\n' > \"$1\"\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&editor, fs::Permissions::from_mode(0o755)).unwrap();
    }
    env.hp()
        .env("EDITOR", &editor)
        .args(["edit", "x"])
        .assert()
        .success();
    assert_eq!(env.show("x"), "new\n");
    assert!(env.git_log()[0].starts_with("Edit password for x using "));

    env.hp()
        .env("EDITOR", "true")
        .args(["edit", "x"])
        .assert()
        .success()
        .stdout(predicate::str::contains("unchanged"));
}

#[test]
fn generate_passphrase() {
    let env = Env::new();
    env.init_with_git();
    env.hp()
        .args(["generate", "--words", "5", "--separator", ".", "phrase"])
        .assert()
        .success();
    let phrase = env.show("phrase");
    let words: Vec<&str> = phrase.trim_end().split('.').collect();
    assert_eq!(words.len(), 5);
    assert!(
        words
            .iter()
            .all(|w| !w.is_empty() && w.chars().all(|c| c.is_ascii_lowercase() || c == '-'))
    );
    env.hp()
        .args(["generate", "--words", "4", "-n", "x"])
        .assert()
        .failure();
}

#[test]
fn hotp_advances_and_commits_the_counter() {
    let env = Env::new();
    env.init_with_git();
    // RFC 4226 secret; counter=0 means the next code uses counter 1.
    env.insert(
        "hotp",
        "pw\notpauth://hotp/Ex:me?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=0&issuer=Ex\n",
    );
    env.hp()
        .args(["otp", "hotp"])
        .assert()
        .success()
        .stdout("287082\n");
    env.hp()
        .args(["otp", "hotp"])
        .assert()
        .success()
        .stdout("359152\n");
    assert_eq!(
        env.show("hotp"),
        "pw\notpauth://hotp/Ex:me?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=2&issuer=Ex\n"
    );
    assert_eq!(env.git_log()[0], "Increment HOTP counter for hotp.");
}

#[test]
fn completes_entry_names() {
    let env = Env::new();
    env.init_with_git();
    env.insert("Email/work", "x\n");
    env.insert("Email/home", "x\n");
    env.insert("Web/github", "x\n");
    let complete = |args: &[&str]| {
        let out = env
            .hp()
            .env("COMPLETE", "fish")
            .arg("--")
            .arg("hidepass")
            .args(args)
            .output()
            .unwrap();
        String::from_utf8(out.stdout).unwrap()
    };
    assert_eq!(complete(&["show", "Em"]), "Email/\n");
    assert_eq!(complete(&["edit", "Email/"]), "Email/home\nEmail/work\n");
    assert_eq!(complete(&["W"]), "Web/\nWeb/github\n");
    assert!(complete(&["ls", ""]).starts_with("Email/\nWeb/\n"));
}
