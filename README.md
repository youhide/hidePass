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
- **Built-in extras:** TOTP and HOTP codes (pass-otp format), diceware passphrases,
  `key: value` fields, a store audit with `check`, QR codes, and shell completion of
  entry names.
- **Private clipboard on macOS:** copied secrets are marked with the nspasteboard.org
  concealed/transient types, so clipboard managers (Maccy, Raycast, Alfred, Paste…)
  don't record them, and the previous clipboard comes back after 45 s.
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

### Shell completion

Homebrew installs completions for bash, zsh and fish. They complete commands and
flags, and also entry names, folder by folder, read live from your store
(`hidepass Em<Tab>` → `Email/`, then `Email/<Tab>` → `Email/work`). Otherwise add one
line to your shell's startup file:

```sh
source <(hidepass completions zsh)     # ~/.zshrc  (or: bash in ~/.bashrc)
hidepass completions fish | source      # ~/.config/fish/config.fish
```

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
| `generate --words N [--separator S] <name>` | Generate a passphrase of N words instead |
| `wallet [-w 12\|24] [-c] [-f] <name>` | Create a BIP39 crypto wallet and store its mnemonic and first BTC/ETH addresses |
| `rm [-r] [-f] <name>` | Remove an entry or folder |
| `mv` / `cp [-f] <old> <new>` | Move or copy, re-encrypting when the destination uses other keys |
| `init [-p sub] <gpg-id>…` | Set the keys for the store or a subfolder and re-encrypt |
| `otp [-c] <name>` | One-time code from an `otpauth://` line (TOTP, or HOTP: advances and commits the counter) |
| `check [--fix] [dir]` | Find (and re-encrypt) entries not encrypted to their `.gpg-id` |
| `git <args>…` | Run git in the store; `git init` also configures gpg diffs |
| `completions <shell>` | Completion script that also completes entry names (bash, zsh, fish, elvish, powershell) |

### Passphrases

`hidepass generate --words 6 Email/work` picks 6 words uniformly from the
[EFF long wordlist](https://www.eff.org/dice) (7776 words, ~12.9 bits each, so 6 words
≈ 77 bits), e.g. `cubicle-unfold-dripping-tribune-ample-reveal`. `--separator` changes
the `-`; `-i`, `-c` and `-f` work as for passwords.

### Crypto wallets

`hidepass wallet crypto/main` creates a new wallet with one command. It generates a
24-word BIP39 mnemonic from the OS CSPRNG (`-w 12` for 12 words), derives the first
receive addresses, and stores everything as one entry:

```
<the 24 words>
type: bip39
btc-path: m/84'/0'/0'/0/0
btc-address: bc1q…
eth-path: m/44'/60'/0'/0/0
eth-address: 0x…
```

The same mnemonic works for Bitcoin and Ethereum (and other chains): import it into
any BIP39 wallet (Sparrow, Electrum, a hardware wallet, MetaMask, …) and it shows these
same addresses. You can hand out an address without decrypting the mnemonic onto the
screen, with `hidepass show --field btc-address crypto/main` or as a QR code with
`hidepass show --field btc-address -q crypto/main`. `-c` copies the mnemonic to the clipboard instead of
printing it. All addresses are mainnet, and no BIP39 passphrase is used.

Overwriting an existing entry is refused unless you pass `-f`; there is no y/N prompt
here, because replacing a mnemonic by accident loses the funds. Remember that if you
push the store to a git remote, the mnemonic goes along with it, encrypted to your gpg
keys like every other entry.

### Entries with fields and one-time codes

The first line is the password. Other lines can hold anything; `key: value` lines can be
read with `--field`, and an `otpauth://` URI enables `hidepass otp`:

```
correct horse battery staple
user: alice@example.com
url: https://example.com
otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example
```

TOTP supports SHA1/SHA256/SHA512, 6–10 digits and custom periods. For
`otpauth://hotp/…?counter=N`, the code uses counter N+1 and the entry is re-encrypted
with the new counter and committed (`Increment HOTP counter for …`), exactly like
pass-otp, so both tools can share HOTP entries without ever repeating a code.

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

The clipboard is the native pasteboard on macOS, `wl-copy` on Wayland and `xclip` on
X11.

### Differences from pass

- pass extensions (`~/.password-store/.extensions`) aren't run; OTP is built in.
- git's commit summaries go to stderr, so stdout only carries the output you asked for.
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

MIT. The EFF long wordlist (`assets/eff_large_wordlist.txt`) is by the Electronic
Frontier Foundation, licensed CC BY 3.0 US. The BIP39 English wordlist
(`assets/bip39_english.txt`) is from [BIP 39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki),
licensed MIT.
