use clap::{Args, Parser, Subcommand};
use clap_complete::Shell;
use clap_complete::engine::{ArgValueCompleter, SubcommandCandidates};

use crate::complete;

#[derive(Parser)]
#[command(
    name = "hidepass",
    version,
    about = "A pass-compatible password manager: same store, same gpg keys, more features.",
    after_help = "Running `hidepass <name>` is the same as `hidepass show <name>`, and `hidepass` alone lists the store.",
    allow_external_subcommands = true,
    add = SubcommandCandidates::new(complete::all_entries)
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Initialize the store (or a subfolder) for the given GPG ids and re-encrypt existing entries.
    Init {
        /// Subfolder to initialize instead of the store root.
        #[arg(short = 'p', long = "path", value_name = "SUBFOLDER", add = ArgValueCompleter::new(complete::folders))]
        subfolder: Option<String>,
        /// GPG ids to encrypt to. A single empty string removes the subfolder's .gpg-id.
        #[arg(required = true, num_args = 1..)]
        gpg_ids: Vec<String>,
    },
    /// List entries as a tree.
    #[command(visible_alias = "list")]
    Ls {
        #[arg(add = ArgValueCompleter::new(complete::folders))]
        subfolder: Option<String>,
    },
    /// Show an entry, or list a folder.
    Show(ShowArgs),
    /// List entries whose names match any of the terms.
    #[command(visible_alias = "search")]
    Find {
        #[arg(required = true, num_args = 1..)]
        terms: Vec<String>,
    },
    /// Search the decrypted contents of every entry with a regular expression.
    Grep {
        #[arg(short = 'i', long)]
        ignore_case: bool,
        pattern: String,
    },
    /// Insert a new entry.
    #[command(visible_alias = "add")]
    Insert {
        /// Echo the password back while typing.
        #[arg(short = 'e', long, conflicts_with = "multiline")]
        echo: bool,
        /// Read multiple lines until EOF (Ctrl+D).
        #[arg(short = 'm', long)]
        multiline: bool,
        /// Overwrite an existing entry without asking.
        #[arg(short = 'f', long)]
        force: bool,
        #[arg(add = ArgValueCompleter::new(complete::entries))]
        name: String,
    },
    /// Edit an entry with $EDITOR, using a RAM-backed temporary file.
    Edit {
        #[arg(add = ArgValueCompleter::new(complete::entries))]
        name: String,
    },
    /// Generate a new password.
    Generate {
        /// Use only letters and digits.
        #[arg(short = 'n', long)]
        no_symbols: bool,
        /// Copy the password to the clipboard instead of printing it.
        #[arg(short = 'c', long)]
        clip: bool,
        /// Replace only the first line of an existing entry.
        #[arg(short = 'i', long, conflicts_with = "force")]
        in_place: bool,
        /// Overwrite an existing entry without asking.
        #[arg(short = 'f', long)]
        force: bool,
        /// Generate a passphrase of N words from the EFF long wordlist instead.
        #[arg(short = 'w', long, value_name = "N", conflicts_with_all = ["no_symbols", "length"])]
        words: Option<usize>,
        /// Separator between passphrase words.
        #[arg(long, value_name = "SEP", default_value = "-", requires = "words")]
        separator: String,
        #[arg(add = ArgValueCompleter::new(complete::entries))]
        name: String,
        /// Length (default: $PASSWORD_STORE_GENERATED_LENGTH or 25).
        length: Option<usize>,
    },
    /// Remove an entry or, with -r, a folder.
    #[command(visible_aliases = ["remove", "delete"])]
    Rm {
        #[arg(short = 'r', long)]
        recursive: bool,
        #[arg(short = 'f', long)]
        force: bool,
        #[arg(add = ArgValueCompleter::new(complete::entries))]
        name: String,
    },
    /// Move or rename an entry or folder, re-encrypting if the destination uses other keys.
    #[command(visible_alias = "rename")]
    Mv {
        #[arg(short = 'f', long)]
        force: bool,
        #[arg(add = ArgValueCompleter::new(complete::entries))]
        old: String,
        #[arg(add = ArgValueCompleter::new(complete::entries))]
        new: String,
    },
    /// Copy an entry or folder, re-encrypting if the destination uses other keys.
    #[command(visible_alias = "copy")]
    Cp {
        #[arg(short = 'f', long)]
        force: bool,
        #[arg(add = ArgValueCompleter::new(complete::entries))]
        old: String,
        #[arg(add = ArgValueCompleter::new(complete::entries))]
        new: String,
    },
    /// Run git inside the store (`hidepass git init` sets up gpg diffs like pass).
    Git {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Print the current one-time code from an entry's otpauth:// URI (TOTP, or HOTP
    /// with the counter advanced and committed).
    Otp {
        #[arg(short = 'c', long)]
        clip: bool,
        #[arg(add = ArgValueCompleter::new(complete::entries))]
        name: String,
    },
    /// Check that every entry is encrypted to the keys in its .gpg-id.
    Check {
        /// Re-encrypt the entries that are not.
        #[arg(long)]
        fix: bool,
        #[arg(add = ArgValueCompleter::new(complete::folders))]
        subfolder: Option<String>,
    },
    /// Print a shell completion script that also completes entry names.
    Completions { shell: Shell },
    /// Print the version.
    Version,
    #[command(name = "__clip-restore", hide = true)]
    ClipRestore { timeout: u64 },
    /// `hidepass <name> ...`, shown like pass does.
    #[command(external_subcommand)]
    External(Vec<String>),
}

#[derive(Args)]
pub struct ShowArgs {
    /// Copy line LINE (default 1) to the clipboard instead of printing.
    #[arg(short = 'c', long, value_name = "LINE", num_args = 0..=1, require_equals = true, default_missing_value = "1")]
    pub clip: Option<usize>,
    /// Show line LINE (default 1) as a QR code.
    #[arg(short = 'q', long, value_name = "LINE", num_args = 0..=1, require_equals = true, default_missing_value = "1")]
    pub qrcode: Option<usize>,
    /// Show only the value of a `key: value` line (`password` is the first line).
    #[arg(long, value_name = "KEY")]
    pub field: Option<String>,
    #[arg(add = ArgValueCompleter::new(complete::entries))]
    pub name: Option<String>,
}

/// Subcommand names and aliases, used to decide when a bare argument is an entry.
pub const COMMANDS: &[&str] = &[
    "init",
    "ls",
    "list",
    "show",
    "find",
    "search",
    "grep",
    "insert",
    "add",
    "edit",
    "generate",
    "rm",
    "remove",
    "delete",
    "mv",
    "rename",
    "cp",
    "copy",
    "git",
    "otp",
    "check",
    "completions",
    "version",
    "help",
    "__clip-restore",
];
