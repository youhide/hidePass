# hidePass

A password manager written in Rust that works with your existing
[pass](https://www.passwordstore.org) store: the same `~/.password-store`, the same
gpg keys, the same git history. Use it in place of `pass`, or alongside it, and add
the things pass leaves to extensions.

```console
$ hidepass
Password Store
├── Email
│   └── work
└── Web
    └── github

$ hidepass -c Web/github
Copied Web/github to clipboard. Will clear in 45 seconds.

$ hidepass otp Web/github
482915
```

## Why

- **Drop-in.** It reads and writes the pass format (`*.gpg`, `.gpg-id`, `.gpg-id.sig`),
  honours the `PASSWORD_STORE_*` variables and makes the same git commits, so pass, the
  iOS/Android apps and browser extensions keep working on the same store. CI checks
  this against the real pass on every push.
- **No deprecated macOS tools.** pass builds its ramdisk with `hdiutil`, which macOS 27
  deprecates (`hdiutil: WARNING: 'hdiutil attach -nomount ...' is deprecated`). hidePass
  uses `diskutil image` for `edit`, and `hidepass git` needs no ramdisk at all, since
  git only ever sees encrypted files.
- **Built-in extras:** TOTP codes (pass-otp format), `key: value` fields, a store audit
  with `check`, QR codes, and shell completions.
- **Safer by default:** entries are written atomically (an interrupted gpg never leaves a
  truncated file), recipients are validated before anything is re-encrypted, passwords
  come from the OS CSPRNG without modulo bias, and decrypted data is zeroed in memory
  once it's no longer needed.

It uses your `gpg` and `git` binaries, so gpg-agent, pinentry, smartcards/YubiKeys,
SSH remotes and signed commits work exactly as they do with pass.

## Install

```sh
brew install youhide/youhide/hidepass
```

Or build from source with Rust 1.88 or newer:

```sh
cargo install --git https://github.com/youhide/hidePass
```

Requires `gpg` (GnuPG 2) and, for git features, `git`. If you're used to typing `pass`,
`alias pass=hidepass` works: the command line is compatible.

## Usage

| Command | |
|---|---|
| `hidepass` / `ls [dir]` | List entries as a tree |
| `hidepass <name>` / `show <name>` | Print an entry |
| `show -c[N] <name>` | Copy line N (default 1) to the clipboard, restored after 45 s |
| `show -q[N] <name>` | Show line N as a QR code |
| `show --field user <name>` | Print the value of a `user: …` line (`password` is line 1) |
| `find <term>…` | List entries whose names match |
| `grep [-i] <regex>` | Search decrypted contents |
| `insert [-e\|-m] [-f] <name>` | Add an entry (prompt, echo, or multiline from stdin) |
| `edit <name>` | Edit with `$EDITOR` in a RAM-backed temp dir |
| `generate [-n] [-c] [-i\|-f] <name> [len]` | Generate a password; `-i` replaces only line 1 |
| `rm [-r] [-f] <name>` | Remove an entry or folder |
| `mv` / `cp [-f] <old> <new>` | Move or copy, re-encrypting when the destination uses other keys |
| `init [-p sub] <gpg-id>…` | Set the keys for the store or a subfolder and re-encrypt |
| `otp [-c] <name>` | Current TOTP code from an `otpauth://totp/…` line |
| `check [--fix] [dir]` | Find (and re-encrypt) entries not encrypted to their `.gpg-id` |
| `git <args>…` | Run git in the store; `git init` also configures gpg diffs |
| `completions <shell>` | Shell completion script (bash, zsh, fish, elvish, powershell) |

### Entries with fields and TOTP

The first line is the password. Other lines can hold anything; `key: value` lines can be
read with `--field`, and an `otpauth://` URI enables `hidepass otp`:

```
correct horse battery staple
user: alice@example.com
url: https://example.com
otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example
```

### Environment

All of pass's variables apply: `PASSWORD_STORE_DIR`, `PASSWORD_STORE_KEY`,
`PASSWORD_STORE_GPG_OPTS`, `PASSWORD_STORE_CLIP_TIME`, `PASSWORD_STORE_X_SELECTION`,
`PASSWORD_STORE_GENERATED_LENGTH`, `PASSWORD_STORE_CHARACTER_SET`,
`PASSWORD_STORE_CHARACTER_SET_NO_SYMBOLS` and `PASSWORD_STORE_SIGNING_KEY` (verifies
`.gpg-id.sig` before encrypting). `git config pass.signcommits true` signs commits.

hidePass adds:

| Variable | |
|---|---|
| `HIDEPASS_CLIP_COPY`, `HIDEPASS_CLIP_PASTE` | Shell commands to use as the clipboard (both must be set), e.g. for tmux or OSC 52 over SSH |
| `HIDEPASS_NO_RAMDISK` | Don't try a ramdisk for `edit`; asks before using the regular temp dir |

The clipboard is `pbcopy` on macOS, `wl-copy` on Wayland and `xclip` on X11.

### Differences from pass

- pass extensions (`~/.password-store/.extensions`) aren't run. OTP is built in; HOTP
  isn't supported yet.
- Listings only show entries and folders, not other files in the store (like a README).

## Development

```sh
cargo test          # unit + end-to-end tests (needs gpg and git; uses a throwaway keyring)
bash .github/scripts/pass-compat.sh target/debug/hidepass   # cross-check against pass
```

Releases: bump `version` in `Cargo.toml`, tag `vX.Y.Z` and push the tag. CI builds
macOS and Linux binaries, publishes the GitHub release and updates the formula in
[youhide/homebrew-youhide](https://github.com/youhide/homebrew-youhide).

## License

MIT
