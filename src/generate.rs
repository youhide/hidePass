//! Password generation from tr(1)-style character sets, compatible with
//! `PASSWORD_STORE_CHARACTER_SET` and `PASSWORD_STORE_CHARACTER_SET_NO_SYMBOLS`.

use std::env;

use anyhow::{Result, bail};
use zeroize::Zeroizing;

pub const DEFAULT_LENGTH: usize = 25;

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

/// Uniformly random password of `length` characters from `set`, using the OS
/// CSPRNG with rejection sampling (no modulo bias).
pub fn password(set: &[u8], length: usize) -> Result<Zeroizing<String>> {
    let n = set.len() as u32;
    let limit = u32::MAX - (u32::MAX % n);
    let mut out = Zeroizing::new(String::with_capacity(length));
    let mut buf = Zeroizing::new([0u8; 256]);
    while out.len() < length {
        getrandom::fill(&mut *buf)?;
        for chunk in buf.as_chunks::<4>().0 {
            let v = u32::from_le_bytes(*chunk);
            if v < limit && out.len() < length {
                out.push(set[(v % n) as usize] as char);
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
    fn generates_from_the_set_only() {
        let pw = password(b"ab", 200).unwrap();
        assert_eq!(pw.len(), 200);
        assert!(pw.chars().all(|c| c == 'a' || c == 'b'));
        assert!(pw.contains('a') && pw.contains('b'));
    }
}
