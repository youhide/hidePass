//! Password generation from tr(1)-style character sets, compatible with
//! `PASSWORD_STORE_CHARACTER_SET` and `PASSWORD_STORE_CHARACTER_SET_NO_SYMBOLS`.

use std::env;

use anyhow::{Result, bail};
use zeroize::Zeroizing;

pub const DEFAULT_LENGTH: usize = 25;

/// The EFF long wordlist (7776 words, about 12.9 bits each), by the Electronic
/// Frontier Foundation, CC BY 3.0 US.
const WORDLIST: &str = include_str!("../assets/eff_large_wordlist.txt");

/// What `generate` makes.
pub enum Recipe {
    /// Random characters; `length` defaults to `$PASSWORD_STORE_GENERATED_LENGTH`.
    Chars {
        length: Option<usize>,
        no_symbols: bool,
    },
    /// A diceware-style passphrase.
    Words { count: usize, separator: String },
}

impl Recipe {
    pub fn generate(&self) -> Result<Zeroizing<String>> {
        match self {
            Recipe::Chars { length, no_symbols } => {
                let length = length.unwrap_or_else(default_length);
                if length == 0 {
                    bail!("pass-length must be greater than zero.");
                }
                password(&charset(*no_symbols)?, length)
            }
            Recipe::Words { count, separator } => {
                if *count == 0 {
                    bail!("the number of words must be greater than zero.");
                }
                passphrase(*count, separator)
            }
        }
    }
}

pub fn default_length() -> usize {
    env::var("PASSWORD_STORE_GENERATED_LENGTH")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_LENGTH)
}

pub fn charset(no_symbols: bool) -> Result<Vec<u8>> {
    let spec = if no_symbols {
        env::var("PASSWORD_STORE_CHARACTER_SET_NO_SYMBOLS").unwrap_or_else(|_| "[:alnum:]".into())
    } else {
        env::var("PASSWORD_STORE_CHARACTER_SET").unwrap_or_else(|_| "[:punct:][:alnum:]".into())
    };
    let set = expand(&spec)?;
    if set.is_empty() {
        bail!("the character set {spec:?} is empty.");
    }
    Ok(set)
}

/// Expands a tr(1)-like set (`[:alnum:]`, `a-z`, literal characters) into the
/// distinct printable ASCII bytes it names, in ascending order.
pub fn expand(spec: &str) -> Result<Vec<u8>> {
    let mut chosen = [false; 128];
    let b = spec.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i..].starts_with(b"[:") {
            let Some(end) = spec[i + 2..].find(":]") else {
                bail!("unterminated class in {spec:?}")
            };
            let class = &spec[i + 2..i + 2 + end];
            let pred: fn(u8) -> bool = match class {
                "alnum" => |c| c.is_ascii_alphanumeric(),
                "alpha" => |c| c.is_ascii_alphabetic(),
                "digit" => |c| c.is_ascii_digit(),
                "lower" => |c| c.is_ascii_lowercase(),
                "upper" => |c| c.is_ascii_uppercase(),
                "punct" => |c| c.is_ascii_punctuation(),
                "xdigit" => |c| c.is_ascii_hexdigit(),
                "graph" | "print" => |c| c.is_ascii_graphic(),
                _ => bail!("unknown character class [:{class}:]"),
            };
            (0u8..128)
                .filter(|&c| pred(c))
                .for_each(|c| chosen[c as usize] = true);
            i += end + 4;
        } else if i + 2 < b.len() && b[i + 1] == b'-' {
            if b[i] > b[i + 2] || !b[i + 2].is_ascii() {
                bail!("invalid range in {spec:?}");
            }
            (b[i]..=b[i + 2])
                .filter(u8::is_ascii_graphic)
                .for_each(|c| chosen[c as usize] = true);
            i += 3;
        } else {
            if b[i].is_ascii_graphic() {
                chosen[b[i] as usize] = true;
            }
            i += 1;
        }
    }
    Ok((0u8..128).filter(|&c| chosen[c as usize]).collect())
}

/// Uniformly random password of `length` characters from `set`.
pub fn password(set: &[u8], length: usize) -> Result<Zeroizing<String>> {
    let mut out = Zeroizing::new(String::with_capacity(length));
    for i in random_indices(set.len(), length)?.iter() {
        out.push(set[*i] as char);
    }
    Ok(out)
}

/// `count` uniformly random words from the EFF long wordlist.
pub fn passphrase(count: usize, separator: &str) -> Result<Zeroizing<String>> {
    let words: Vec<&str> = WORDLIST.lines().collect();
    let mut out = Zeroizing::new(String::new());
    for (n, i) in random_indices(words.len(), count)?.iter().enumerate() {
        if n > 0 {
            out.push_str(separator);
        }
        out.push_str(words[*i]);
    }
    Ok(out)
}

/// `count` uniform indices in `0..n` from the OS CSPRNG, using rejection
/// sampling so there is no modulo bias.
fn random_indices(n: usize, count: usize) -> Result<Zeroizing<Vec<usize>>> {
    let n = u32::try_from(n).expect("small set");
    let limit = u32::MAX - (u32::MAX % n);
    let mut out = Zeroizing::new(Vec::with_capacity(count));
    let mut buf = Zeroizing::new([0u8; 256]);
    while out.len() < count {
        getrandom::fill(&mut *buf)?;
        for chunk in buf.as_chunks::<4>().0 {
            let v = u32::from_le_bytes(*chunk);
            if v < limit && out.len() < count {
                out.push((v % n) as usize);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_classes_ranges_and_literals() {
        assert_eq!(expand("[:digit:]").unwrap(), b"0123456789");
        assert_eq!(expand("a-dX_").unwrap(), b"X_abcd");
        assert_eq!(expand("[:alnum:]").unwrap().len(), 62);
        assert_eq!(expand("[:punct:][:alnum:]").unwrap().len(), 94);
        assert!(expand("[:nope:]").is_err());
    }

    #[test]
    fn wordlist_is_the_eff_long_list() {
        let words: Vec<&str> = WORDLIST.lines().collect();
        assert_eq!(words.len(), 7776);
        assert_eq!((words[0], words[7775]), ("abacus", "zoom"));
    }

    #[test]
    fn passphrases_use_wordlist_words() {
        let phrase = passphrase(6, " ").unwrap();
        let parts: Vec<&str> = phrase.split(' ').collect();
        assert_eq!(parts.len(), 6);
        assert!(parts.iter().all(|w| WORDLIST.lines().any(|l| l == *w)));
    }

    #[test]
    fn generates_from_the_set_only() {
        let pw = password(b"ab", 200).unwrap();
        assert_eq!(pw.len(), 200);
        assert!(pw.chars().all(|c| c == 'a' || c == 'b'));
        assert!(pw.contains('a') && pw.contains('b'));
    }
}
