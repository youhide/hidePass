mod cli;
mod clip;
mod commands;
mod generate;
mod git;
mod gpg;
mod otp;
mod store;
mod term;
mod tmp;

use std::process::ExitCode;

use clap::{CommandFactory, Parser};

use cli::{COMMANDS, Cli, Command};
use commands::Ctx;

fn main() -> ExitCode {
    let cli = Cli::parse_from(normalize_args(std::env::args().collect()));
    match run(cli) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("Error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

/// pass treats an unknown first argument as an entry to show (`pass Email/work`,
/// `pass -c Email/work`) and no arguments as `pass ls`. It also accepts the line
/// number glued to the flag (`-c2`), which clap reads as `--clip=2`.
fn normalize_args(mut args: Vec<String>) -> Vec<String> {
    match args.get(1).map(String::as_str) {
        None => args.push("ls".into()),
        Some("-h" | "--help" | "-V" | "--version") => {}
        Some(first) if !COMMANDS.contains(&first) => args.insert(1, "show".into()),
        Some(_) => {}
    }
    if args.get(1).is_some_and(|a| a == "show") {
        for arg in args.iter_mut().skip(2) {
            if arg == "--" {
                break;
            }
            for (short, long) in [("-c", "--clip"), ("-q", "--qrcode")] {
                if let Some(n) = arg.strip_prefix(short)
                    && !n.is_empty()
                    && n.bytes().all(|b| b.is_ascii_digit())
                {
                    *arg = format!("{long}={n}");
                }
            }
        }
    }
    args
}

fn run(cli: Cli) -> anyhow::Result<u8> {
    let command = match cli.command {
        Command::Version => {
            println!("hidepass {}", env!("CARGO_PKG_VERSION"));
            return Ok(0);
        }
        Command::Completions { shell } => {
            clap_complete::generate(
                shell,
                &mut Cli::command(),
                "hidepass",
                &mut std::io::stdout(),
            );
            return Ok(0);
        }
        Command::ClipRestore { timeout } => {
            clip::restore(timeout)?;
            return Ok(0);
        }
        other => other,
    };

    let ctx = Ctx::new()?;
    match command {
        Command::Init { subfolder, gpg_ids } => commands::init(&ctx, subfolder, gpg_ids)?,
        Command::Ls { subfolder } => commands::ls(&ctx, subfolder)?,
        Command::Show(args) => commands::show(&ctx, args)?,
        Command::Find { terms } => commands::find(&ctx, terms)?,
        Command::Grep {
            ignore_case,
            pattern,
        } => commands::grep(&ctx, &pattern, ignore_case)?,
        Command::Insert {
            echo,
            multiline,
            force,
            name,
        } => commands::insert(&ctx, &name, echo, multiline, force)?,
        Command::Edit { name } => commands::edit(&ctx, &name)?,
        Command::Generate {
            no_symbols,
            clip,
            in_place,
            force,
            name,
            length,
        } => commands::generate(&ctx, &name, length, no_symbols, clip, in_place, force)?,
        Command::Rm {
            recursive,
            force,
            name,
        } => commands::rm(&ctx, &name, recursive, force)?,
        Command::Mv { force, old, new } => commands::mv_or_cp(&ctx, &old, &new, force, true)?,
        Command::Cp { force, old, new } => commands::mv_or_cp(&ctx, &old, &new, force, false)?,
        Command::Git { args } => {
            let code = commands::git(&ctx, args)?;
            return Ok(u8::try_from(code).unwrap_or(1));
        }
        Command::Otp { clip, name } => commands::otp(&ctx, &name, clip)?,
        Command::Check { fix, subfolder } => commands::check(&ctx, subfolder, fix)?,
        Command::Version | Command::Completions { .. } | Command::ClipRestore { .. } => {
            unreachable!()
        }
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::normalize_args;

    fn norm(args: &[&str]) -> Vec<String> {
        let mut v = vec!["hidepass".to_string()];
        v.extend(args.iter().map(|s| s.to_string()));
        normalize_args(v)[1..].to_vec()
    }

    #[test]
    fn bare_names_and_flags_mean_show() {
        assert_eq!(norm(&[]), ["ls"]);
        assert_eq!(norm(&["Email/work"]), ["show", "Email/work"]);
        assert_eq!(norm(&["-c", "Email/work"]), ["show", "-c", "Email/work"]);
        assert_eq!(
            norm(&["-c2", "Email/work"]),
            ["show", "--clip=2", "Email/work"]
        );
        assert_eq!(norm(&["show", "-q3", "x"]), ["show", "--qrcode=3", "x"]);
        assert_eq!(norm(&["generate", "-c", "x"]), ["generate", "-c", "x"]);
        assert_eq!(norm(&["--version"]), ["--version"]);
    }
}
