//! Small terminal helpers: colour detection, prompts and PATH lookups.

use std::env;
use std::io::{self, BufRead, IsTerminal, Write};

pub fn stdout_color() -> bool {
    io::stdout().is_terminal() && env::var_os("NO_COLOR").is_none()
}

pub fn stdin_is_tty() -> bool {
    io::stdin().is_terminal()
}

/// Asks a yes/no question, defaulting to no. Like pass, a non-interactive stdin
/// counts as yes so scripts keep working.
pub fn yesno(question: &str) -> bool {
    if !stdin_is_tty() {
        return true;
    }
    eprint!("{question} [y/N] ");
    let _ = io::stderr().flush();
    let mut answer = String::new();
    if io::stdin().lock().read_line(&mut answer).is_err() {
        return false;
    }
    matches!(answer.trim(), "y" | "Y" | "yes" | "Yes" | "YES")
}

pub fn in_path(bin: &str) -> bool {
    env::var_os("PATH")
        .is_some_and(|paths| env::split_paths(&paths).any(|dir| dir.join(bin).is_file()))
}
