//! The user-facing commands. Messages and git commit messages follow pass so
//! both tools can be used on the same store.

use std::collections::{BTreeSet, HashMap};
use std::env;
use std::fs;
use std::io::{self, BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use anyhow::{Context, Result, bail};
use zeroize::Zeroizing;

use crate::clip;
use crate::generate;
use crate::git::{self, Git};
use crate::gpg::Gpg;
use crate::otp::{self, Kind, Otp};
use crate::store::{self, GPG_ID, Store};
use crate::term;
use crate::tmp::SecureDir;
use crate::wallet::{self, Wallet};

pub struct Ctx {
    pub store: Store,
    pub gpg: Gpg,
    git: Option<Git>,
}

impl Ctx {
    pub fn new() -> Result<Ctx> {
        let store = Store::open()?;
        let git = Git::detect(&store.root);
        Ok(Ctx {
            store,
            gpg: Gpg::new(),
            git,
        })
    }

    fn commit(&self, paths: &[&Path], message: &str) -> Result<()> {
        match &self.git {
            Some(git) => git.commit(paths, message),
            None => Ok(()),
        }
    }

    fn require_store(&self) -> Result<()> {
        if !self.store.root.is_dir() {
            bail!("password store is empty. Try \"hidepass init\".");
        }
        Ok(())
    }

    fn encrypt_entry(&self, plaintext: &[u8], path: &Path) -> Result<()> {
        let recipients = self.store.recipients(&self.gpg, path)?;
        self.gpg.encrypt(plaintext, &recipients, path)
    }
}

pub fn init(ctx: &Ctx, subfolder: Option<String>, ids: Vec<String>) -> Result<()> {
    let sub = Store::clean_name(subfolder.as_deref().unwrap_or(""))?;
    let dir = ctx.store.dir_path(&sub);
    let id_file = dir.join(GPG_ID);
    let suffix = if sub.is_empty() {
        String::new()
    } else {
        format!(" ({sub})")
    };

    if ids.len() == 1 && ids[0].is_empty() {
        if !id_file.is_file() {
            bail!(
                "{} does not exist and so cannot be removed.",
                id_file.display()
            );
        }
        fs::remove_file(&id_file)?;
        let _ = fs::remove_file(store::sig_path(&id_file));
        println!("Removed {}", id_file.display());
        ctx.commit(
            &[&id_file, &store::sig_path(&id_file)],
            &format!("Deinitialize {}{suffix}.", id_file.display()),
        )?;
        let _ = fs::remove_dir(&dir);
    } else {
        // Refuse ids without a usable public encryption key before writing anything.
        ctx.gpg.encryption_key_ids(&ids)?;
        fs::create_dir_all(&dir)?;
        fs::write(
            &id_file,
            ids.iter().map(|i| format!("{i}\n")).collect::<String>(),
        )?;
        let id_print = ids.join(", ");
        println!("Password store initialized for {id_print}{suffix}");
        ctx.commit(&[&id_file], &format!("Set GPG id to {id_print}{suffix}."))?;

        if let Ok(signing) = env::var("PASSWORD_STORE_SIGNING_KEY") {
            let keys: Vec<String> = signing.split_whitespace().map(String::from).collect();
            if !keys.is_empty() {
                ctx.gpg.sign_detached(&id_file, &keys)?;
                ctx.commit(
                    &[&store::sig_path(&id_file)],
                    &format!("Signing new GPG id with {}.", keys.join(",")),
                )?;
            }
        }
    }

    reencrypt(ctx, &dir, true)?;
    ctx.commit(
        &[&dir],
        &format!(
            "Reencrypt password store using new GPG id {}{suffix}.",
            ids.join(", ")
        ),
    )
}

/// Re-encrypts every entry under `path` whose recipients differ from its
/// `.gpg-id`. Returns the number of entries that were (or, with `fix` false,
/// would be) re-encrypted.
fn reencrypt(ctx: &Ctx, path: &Path, fix: bool) -> Result<usize> {
    if !path.exists() {
        return Ok(0);
    }
    // Resolve and validate every entry's recipients before touching any file, so
    // a bad .gpg-id or signature aborts without leaving the store half-converted.
    let mut wanted_by_id_file: HashMap<PathBuf, BTreeSet<String>> = HashMap::new();
    let mut stale = Vec::new();
    for entry in ctx.store.entries(path)? {
        let recipients = ctx.store.recipients(&ctx.gpg, &entry)?;
        let id_file = ctx.store.gpg_id_file(&entry).unwrap_or_default();
        let wanted = match wanted_by_id_file.get(&id_file) {
            Some(w) => w.clone(),
            None => {
                let w = ctx.gpg.encryption_key_ids(&recipients)?;
                wanted_by_id_file.insert(id_file, w.clone());
                w
            }
        };
        if ctx.gpg.encrypted_to(&entry)? != wanted {
            stale.push((entry, recipients, wanted));
        }
    }
    for (entry, recipients, wanted) in &stale {
        let name = ctx.store.name_of(entry);
        if !fix {
            println!("{name}: needs re-encryption");
            continue;
        }
        println!(
            "{name}: reencrypting to {}",
            wanted.iter().cloned().collect::<Vec<_>>().join(" ")
        );
        let plaintext = ctx.gpg.decrypt(entry)?;
        ctx.gpg.encrypt(&plaintext, recipients, entry)?;
    }
    Ok(stale.len())
}

pub fn check(ctx: &Ctx, subfolder: Option<String>, fix: bool) -> Result<()> {
    ctx.require_store()?;
    let sub = Store::clean_name(subfolder.as_deref().unwrap_or(""))?;
    let dir = ctx.store.dir_path(&sub);
    let total = ctx.store.entries(&dir)?.len();
    let bad = reencrypt(ctx, &dir, fix)?;
    if fix && bad > 0 {
        ctx.commit(
            &[&dir],
            &format!("Reencrypt {bad} entries to match their .gpg-id."),
        )?;
    }
    match (bad, fix) {
        (0, _) => println!("All {total} entries are encrypted to the right keys."),
        (n, true) => println!("Re-encrypted {n} of {total} entries."),
        (n, false) => {
            bail!("{n} of {total} entries need re-encryption; run `hidepass check --fix`.")
        }
    }
    Ok(())
}

pub fn ls(ctx: &Ctx, subfolder: Option<String>) -> Result<()> {
    show(
        ctx,
        crate::cli::ShowArgs {
            clip: None,
            qrcode: None,
            field: None,
            name: subfolder,
        },
    )
}

pub fn show(ctx: &Ctx, args: crate::cli::ShowArgs) -> Result<()> {
    let name = Store::clean_name(args.name.as_deref().unwrap_or(""))?;
    let file = ctx.store.entry_path(&name);
    if !name.is_empty() && file.is_file() {
        let contents = ctx.gpg.decrypt(&file)?;
        let selected = if let Some(field) = &args.field {
            Some(
                field_value(&contents, field)
                    .with_context(|| format!("there is no {field:?} field in {name}."))?,
            )
        } else {
            args.clip
                .or(args.qrcode)
                .map(|n| line(&contents, n, &name))
                .transpose()?
        };
        match selected {
            Some(value) if args.clip.is_some() => clip::copy(value.as_bytes(), &name),
            Some(value) if args.qrcode.is_some() => qrcode(&value),
            Some(value) => {
                println!("{}", *value);
                Ok(())
            }
            None => {
                io::stdout().write_all(&contents)?;
                Ok(())
            }
        }
    } else {
        let dir = ctx.store.dir_path(&name);
        if name.is_empty() {
            ctx.require_store()?;
            store::print_tree(&dir, Some("Password Store"), &|_| true)
        } else if dir.is_dir() {
            store::print_tree(&dir, Some(&name), &|_| true)
        } else {
            bail!("{name} is not in the password store.")
        }
    }
}

fn line(contents: &[u8], n: usize, name: &str) -> Result<Zeroizing<String>> {
    let text = String::from_utf8_lossy(contents);
    let value = text.lines().nth(n.saturating_sub(1)).unwrap_or("");
    if n == 0 || value.is_empty() {
        bail!("there is no password to put on the clipboard at line {n} of {name}.");
    }
    Ok(Zeroizing::new(value.to_string()))
}

/// Value of a `key: value` line, case-insensitively. `password` falls back to
/// the first line, which is where pass keeps the password.
fn field_value(contents: &[u8], key: &str) -> Option<Zeroizing<String>> {
    let text = String::from_utf8_lossy(contents);
    let found = text.lines().skip(1).find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim()
            .eq_ignore_ascii_case(key)
            .then(|| v.trim().to_string())
    });
    match found {
        Some(v) => Some(Zeroizing::new(v)),
        None if key.eq_ignore_ascii_case("password") => text
            .lines()
            .next()
            .filter(|l| !l.is_empty())
            .map(|l| Zeroizing::new(l.to_string())),
        None => None,
    }
}

fn qrcode(value: &str) -> Result<()> {
    let code = qrcode::QrCode::new(value.as_bytes()).context("value is too long for a QR code")?;
    let image = code
        .render::<qrcode::render::unicode::Dense1x2>()
        .dark_color(qrcode::render::unicode::Dense1x2::Light)
        .light_color(qrcode::render::unicode::Dense1x2::Dark)
        .quiet_zone(true)
        .build();
    println!("{image}");
    Ok(())
}

pub fn find(ctx: &Ctx, terms: Vec<String>) -> Result<()> {
    ctx.require_store()?;
    println!("Search Terms: {}", terms.join(","));
    let terms: Vec<String> = terms.iter().map(|t| t.to_lowercase()).collect();
    store::print_tree(&ctx.store.root, None, &|name| {
        let name = name.to_lowercase();
        terms.iter().any(|t| name.contains(t.as_str()))
    })
}

pub fn grep(ctx: &Ctx, pattern: &str, ignore_case: bool) -> Result<()> {
    ctx.require_store()?;
    let re = regex::RegexBuilder::new(pattern)
        .case_insensitive(ignore_case)
        .build()?;
    let color = term::stdout_color();
    for entry in ctx.store.entries(&ctx.store.root)? {
        let contents = ctx.gpg.decrypt(&entry)?;
        let text = Zeroizing::new(String::from_utf8_lossy(&contents).into_owned());
        let matches: Vec<&str> = text.lines().filter(|l| re.is_match(l)).collect();
        if matches.is_empty() {
            continue;
        }
        let name = ctx.store.name_of(&entry);
        let (dir, base) = match name.rsplit_once('/') {
            Some((d, b)) => (format!("{d}/"), b.to_string()),
            None => (String::new(), name.clone()),
        };
        if color {
            println!("\x1b[94m{dir}\x1b[1m{base}\x1b[0m:");
        } else {
            println!("{dir}{base}:");
        }
        for l in matches {
            if color {
                println!("{}", re.replace_all(l, "\x1b[01;31m$0\x1b[0m"));
            } else {
                println!("{l}");
            }
        }
    }
    Ok(())
}

pub fn insert(ctx: &Ctx, name: &str, echo: bool, multiline: bool, force: bool) -> Result<()> {
    let name = Store::clean_name(name)?;
    let path = ctx.store.entry_path(&name);
    // Resolve recipients first so a missing .gpg-id fails before prompting.
    ctx.store.recipients(&ctx.gpg, &path)?;
    if !force
        && path.exists()
        && !term::yesno(&format!(
            "An entry already exists for {name}. Overwrite it?"
        ))
    {
        bail!("aborted.");
    }

    let contents: Zeroizing<Vec<u8>> = if multiline {
        println!("Enter contents of {name} and press Ctrl+D when finished:\n");
        let mut buf = Zeroizing::new(Vec::new());
        io::stdin().read_to_end(&mut buf)?;
        buf
    } else if echo || !term::stdin_is_tty() {
        if term::stdin_is_tty() {
            eprint!("Enter password for {name}: ");
            io::stderr().flush()?;
        }
        let mut line = Zeroizing::new(String::new());
        io::stdin().lock().read_line(&mut line)?;
        let trimmed = line.trim_end_matches(['\n', '\r']);
        Zeroizing::new(format!("{trimmed}\n").into_bytes())
    } else {
        let first = Zeroizing::new(rpassword::prompt_password(format!(
            "Enter password for {name}: "
        ))?);
        let second = Zeroizing::new(rpassword::prompt_password(format!(
            "Retype password for {name}: "
        ))?);
        if *first != *second {
            bail!("the entered passwords do not match.");
        }
        Zeroizing::new(format!("{}\n", *first).into_bytes())
    };

    ctx.encrypt_entry(&contents, &path)?;
    ctx.commit(
        &[&path],
        &format!("Add given password for {name} to store."),
    )
}

pub fn edit(ctx: &Ctx, name: &str) -> Result<()> {
    let name = Store::clean_name(name)?;
    let path = ctx.store.entry_path(&name);
    ctx.store.recipients(&ctx.gpg, &path)?;

    let secure = SecureDir::new()?;
    let tmp_file = secure
        .path()
        .join(format!("{}.txt", name.replace('/', "-")));
    let original = if path.is_file() {
        Some(ctx.gpg.decrypt(&path)?)
    } else {
        None
    };
    write_private(
        &tmp_file,
        original.as_deref().map(|v| &v[..]).unwrap_or_default(),
    )?;

    let editor = env::var("EDITOR")
        .ok()
        .filter(|e| !e.is_empty())
        .unwrap_or_else(|| "vi".into());
    // Keep running through ^C in the editor so the secure dir is always cleaned up.
    let _sigint = signal_hook::flag::register(
        signal_hook::consts::SIGINT,
        Arc::new(AtomicBool::new(false)),
    )?;
    let status = Command::new("sh")
        .arg("-c")
        .arg(format!("{editor} \"$1\""))
        .arg("sh")
        .arg(&tmp_file)
        .status()
        .with_context(|| format!("could not run {editor}"))?;
    if !status.success() {
        bail!("{editor} exited with an error; {name} was not changed.");
    }
    let Ok(edited) = fs::read(&tmp_file).map(Zeroizing::new) else {
        bail!("new password not saved.");
    };
    if original.as_deref() == Some(&edited) {
        println!("Password for {name} unchanged.");
        return Ok(());
    }
    ctx.encrypt_entry(&edited, &path)?;
    let verb = if original.is_some() { "Edit" } else { "Add" };
    ctx.commit(
        &[&path],
        &format!("{verb} password for {name} using {editor}."),
    )
}

fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)?;
    Ok(())
}

pub fn generate(
    ctx: &Ctx,
    name: &str,
    recipe: generate::Recipe,
    clip_it: bool,
    in_place: bool,
    force: bool,
) -> Result<()> {
    let name = Store::clean_name(name)?;
    let password = recipe.generate()?;
    let path = ctx.store.entry_path(&name);
    ctx.store.recipients(&ctx.gpg, &path)?;
    let exists = path.is_file();
    if in_place && !exists {
        bail!("{name} does not exist, so it cannot be changed in place.");
    }
    if !in_place
        && !force
        && exists
        && !term::yesno(&format!(
            "An entry already exists for {name}. Overwrite it?"
        ))
    {
        bail!("aborted.");
    }

    let (contents, verb) = if in_place {
        let old = ctx.gpg.decrypt(&path)?;
        let rest = old
            .iter()
            .position(|&b| b == b'\n')
            .map(|i| &old[i + 1..])
            .unwrap_or_default();
        let mut new = Zeroizing::new(format!("{}\n", *password).into_bytes());
        new.extend_from_slice(rest);
        (new, "Replace")
    } else {
        (
            Zeroizing::new(format!("{}\n", *password).into_bytes()),
            "Add",
        )
    };
    ctx.encrypt_entry(&contents, &path)?;
    ctx.commit(&[&path], &format!("{verb} generated password for {name}."))?;

    if clip_it {
        clip::copy(password.as_bytes(), &name)
    } else if term::stdout_color() {
        println!(
            "\x1b[1mThe generated password for \x1b[4m{name}\x1b[24m is:\x1b[0m\n\x1b[1m\x1b[93m{}\x1b[0m",
            *password
        );
        Ok(())
    } else {
        println!("The generated password for {name} is:\n{}", *password);
        Ok(())
    }
}

/// Creates a BIP39 wallet in a new entry. Unlike `generate`, an existing entry
/// is only replaced with --force: losing a mnemonic means losing the funds, and
/// `yesno` says yes when stdin is not a terminal.
pub fn wallet(ctx: &Ctx, name: &str, words: usize, clip_it: bool, force: bool) -> Result<()> {
    let name = Store::clean_name(name)?;
    let path = ctx.store.entry_path(&name);
    ctx.store.recipients(&ctx.gpg, &path)?;
    if !force && path.exists() {
        bail!("{name} already exists; refusing to overwrite a wallet (use --force).");
    }
    let wallet = Wallet::create(words)?;
    ctx.encrypt_entry(&wallet.entry(), &path)?;
    ctx.commit(&[&path], &format!("Add wallet for {name}."))?;

    let color = term::stdout_color();
    if !clip_it {
        let mut grid = Zeroizing::new(String::new());
        for (i, word) in wallet.mnemonic.split(' ').enumerate() {
            if i % 4 == 3 {
                grid.push_str(&format!("{:>2}. {word}\n", i + 1));
            } else {
                grid.push_str(&format!("{:>2}. {word:<8}  ", i + 1));
            }
        }
        if color {
            println!(
                "\x1b[1mThe mnemonic for \x1b[4m{name}\x1b[24m is:\x1b[0m\n\x1b[1m\x1b[93m{}\x1b[0m",
                grid.trim_end()
            );
        } else {
            println!("The mnemonic for {name} is:\n{}", grid.trim_end());
        }
    }
    let (b, r) = if color {
        ("\x1b[1m", "\x1b[0m")
    } else {
        ("", "")
    };
    println!("{b}BTC{r}  {}  {}", wallet.btc_address, wallet::BTC_PATH);
    println!("{b}ETH{r}  {}  {}", wallet.eth_address, wallet::ETH_PATH);
    if clip_it {
        clip::copy(wallet.mnemonic.as_bytes(), &name)?;
    }
    Ok(())
}

/// Resolves a user-given name to an existing file or directory, preferring the
/// entry unless the name ends with `/` (pass semantics).
fn resolve(ctx: &Ctx, raw: &str) -> Result<(String, PathBuf, bool)> {
    let name = Store::clean_name(raw)?;
    let file = ctx.store.entry_path(&name);
    let dir = ctx.store.dir_path(&name);
    let want_dir = raw.ends_with('/') || !file.is_file();
    if want_dir && dir.is_dir() && !name.is_empty() {
        Ok((name, dir, true))
    } else if file.is_file() {
        Ok((name, file, false))
    } else {
        bail!("{raw} is not in the password store.")
    }
}

pub fn rm(ctx: &Ctx, raw: &str, recursive: bool, force: bool) -> Result<()> {
    let (name, path, is_dir) = resolve(ctx, raw)?;
    if is_dir && !recursive {
        bail!("{name} is a directory; use -r to remove it.");
    }
    if !force && !term::yesno(&format!("Are you sure you would like to delete {name}?")) {
        bail!("aborted.");
    }
    if is_dir {
        fs::remove_dir_all(&path)?;
    } else {
        fs::remove_file(&path)?;
    }
    println!("Removed {name}.");
    ctx.commit(&[&path], &format!("Remove {name} from store."))?;
    store::prune_empty_dirs(&ctx.store.root, &path);
    Ok(())
}

pub fn mv_or_cp(ctx: &Ctx, old_raw: &str, new_raw: &str, force: bool, mv: bool) -> Result<()> {
    let (_, old_path, is_dir) = resolve(ctx, old_raw)?;
    let new_name = Store::clean_name(new_raw)?;
    let new_dir = ctx.store.dir_path(&new_name);
    let target = if new_raw.ends_with('/') || new_dir.is_dir() || new_name.is_empty() {
        new_dir.join(old_path.file_name().context("cannot move the store root")?)
    } else if is_dir {
        new_dir
    } else {
        ctx.store.entry_path(&new_name)
    };
    if target == old_path || target.starts_with(&old_path) && is_dir {
        bail!(
            "cannot {} {old_raw} into itself.",
            if mv { "move" } else { "copy" }
        );
    }
    if target.exists() {
        if target.is_dir() != is_dir {
            bail!(
                "{} already exists and is a different kind of entry.",
                ctx.store.name_of(&target)
            );
        }
        if !force
            && !term::yesno(&format!(
                "{} already exists. Overwrite it?",
                ctx.store.name_of(&target)
            ))
        {
            bail!("aborted.");
        }
        if is_dir {
            fs::remove_dir_all(&target)?;
        }
    }
    fs::create_dir_all(target.parent().expect("inside the store"))?;
    if mv {
        fs::rename(&old_path, &target)?;
    } else {
        copy_recursive(&old_path, &target)?;
    }
    reencrypt(ctx, &target, true)?;

    if mv {
        ctx.commit(
            &[&old_path, &target],
            &format!("Rename {old_raw} to {new_raw}."),
        )?;
        store::prune_empty_dirs(&ctx.store.root, &old_path);
    } else {
        ctx.commit(&[&target], &format!("Copy {old_raw} to {new_raw}."))?;
    }
    Ok(())
}

fn copy_recursive(from: &Path, to: &Path) -> Result<()> {
    if from.is_dir() {
        fs::create_dir_all(to)?;
        for entry in fs::read_dir(from)? {
            let entry = entry?;
            copy_recursive(&entry.path(), &to.join(entry.file_name()))?;
        }
    } else {
        fs::copy(from, to)?;
    }
    Ok(())
}

pub fn git(ctx: &Ctx, args: Vec<String>) -> Result<i32> {
    if args.first().is_some_and(|a| a == "init") {
        git::init(&ctx.store.root, &args, &ctx.gpg.textconv())?;
        return Ok(0);
    }
    if ctx.git.is_none() {
        bail!("the password store is not a git repository. Try \"hidepass git init\".");
    }
    let status = Command::new("git")
        .arg("-C")
        .arg(&ctx.store.root)
        .args(&args)
        .status()?;
    Ok(status.code().unwrap_or(1))
}

pub fn otp(ctx: &Ctx, name: &str, clip_it: bool) -> Result<()> {
    let name = Store::clean_name(name)?;
    let path = ctx.store.entry_path(&name);
    if !path.is_file() {
        bail!("{name} is not in the password store.");
    }
    let contents = ctx.gpg.decrypt(&path)?;
    let text = Zeroizing::new(String::from_utf8_lossy(&contents).into_owned());
    let otp = Otp::from_entry(&text)?;
    let (code, remaining) = match otp.kind {
        Kind::Totp { period } => {
            let (code, remaining) = otp.now(period);
            (code, Some(remaining))
        }
        Kind::Hotp { counter } => {
            // Store the advanced counter before showing the code, so a code is
            // never shown twice (same scheme and commit as pass-otp).
            let next = counter + 1;
            let updated = Zeroizing::new(otp::with_counter(&text, next));
            ctx.encrypt_entry(updated.as_bytes(), &path)?;
            ctx.commit(&[&path], &format!("Increment HOTP counter for {name}."))?;
            (otp.code(next), None)
        }
    };
    if clip_it {
        return clip::copy(code.as_bytes(), &format!("the OTP code for {name}"));
    }
    println!("{code}");
    if let Some(remaining) = remaining
        && term::stdout_color()
    {
        eprintln!("(valid for {remaining}s)");
    }
    Ok(())
}
