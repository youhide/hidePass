#!/usr/bin/env bash
# Cross-compatibility check between hidepass and pass on a throwaway keyring:
# entries, .gpg-id files and git history written by one must work with the other.
set -euo pipefail

hp="$(realpath "$1")"
work="$(mktemp -d)"
trap 'gpgconf --kill all >/dev/null 2>&1 || true; rm -rf "$work"' EXIT
export GNUPGHOME="$work/gnupg" PASSWORD_STORE_DIR="$work/store"
export GIT_AUTHOR_NAME=ci GIT_AUTHOR_EMAIL=ci@test GIT_COMMITTER_NAME=ci GIT_COMMITTER_EMAIL=ci@test
mkdir -m 700 "$GNUPGHOME"

for who in alice bob; do
  gpg -q --batch --passphrase '' --quick-gen-key "$who <$who@test>" ed25519 cert,sign never
  fpr="$(gpg --with-colons --list-keys "$who@test" | awk -F: '/^fpr/{print $10; exit}')"
  gpg -q --batch --passphrase '' --quick-add-key "$fpr" cv25519 encr never
done

check() { [ "$1" = "$2" ] || { echo "FAIL: $3: got [$1], want [$2]" >&2; exit 1; }; echo "ok: $3"; }

pass init alice@test >/dev/null
pass git init -q

printf 'from-pass\nuser: alice\n' | pass insert -m -f Email/work >/dev/null
check "$("$hp" show Email/work)" "$(printf 'from-pass\nuser: alice')" "hidepass reads pass entries"
check "$("$hp" show --field user Email/work)" "alice" "hidepass --field"

echo 'from-hidepass' | "$hp" insert Social/x >/dev/null
check "$(pass show Social/x)" "from-hidepass" "pass reads hidepass entries"

"$hp" generate -n Web/github 20 >/dev/null
check "$(pass show Web/github | head -1 | tr -d '\n' | wc -c | tr -d ' ')" "20" "pass reads generated entries"

"$hp" init -p Shared alice@test bob@test >/dev/null
"$hp" mv Social/x Shared/ >/dev/null
check "$(pass show Shared/x)" "from-hidepass" "pass reads entries re-encrypted by mv"

pass mv Email/work Shared/work >/dev/null
check "$("$hp" check | tail -1)" "All 3 entries are encrypted to the right keys." "hidepass check after pass mv"

check "$(pass ls | wc -l | tr -d ' ')" "$("$hp" ls | wc -l | tr -d ' ')" "same number of lines in ls"

check "$(git -C "$PASSWORD_STORE_DIR" log --format=%s | sed -n '1p;2p;4p' | paste -sd '|' -)" \
  "Rename Email/work to Shared/work.|Rename Social/x to Shared/.|Add generated password for Web/github." \
  "commit messages"
