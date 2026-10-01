//! One-time codes from `otpauth://` URIs, the format used by pass-otp, so
//! existing entries work without the extension: TOTP (RFC 6238) and HOTP
//! (RFC 4226).

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use hmac::{EagerHash, Hmac, KeyInit, Mac};
use zeroize::Zeroizing;

#[derive(Debug, PartialEq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Debug, PartialEq)]
pub enum Kind {
    Totp {
        period: u64,
    },
    /// `counter` is the last value used; the next code uses `counter + 1`,
    /// like pass-otp.
    Hotp {
        counter: u64,
    },
}

#[derive(Debug)]
pub struct Otp {
    secret: Zeroizing<Vec<u8>>,
    pub algorithm: Algorithm,
    pub digits: u32,
    pub kind: Kind,
}

impl Otp {
    /// Finds and parses the first otpauth URI in an entry.
    pub fn from_entry(contents: &str) -> Result<Otp> {
        Otp::parse(otp_line(contents).context("no otpauth:// URI found in this entry.")?)
    }

    pub fn parse(uri: &str) -> Result<Otp> {
        let rest = uri
            .strip_prefix("otpauth://")
            .context("not an otpauth:// URI")?;
        let (kind, rest) = rest.split_once('/').context("malformed otpauth URI")?;
        let kind = kind.to_ascii_lowercase();
        let query = rest.split_once('?').map(|(_, q)| q).unwrap_or("");
        let mut secret = None;
        let mut otp = Otp {
            secret: Zeroizing::new(Vec::new()),
            algorithm: Algorithm::Sha1,
            digits: 6,
            kind: Kind::Totp { period: 30 },
        };
        let mut period = 30;
        let mut counter = None;
        for pair in query.split('&') {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            match k.to_ascii_lowercase().as_str() {
                "secret" => secret = Some(decode_base32(v)?),
                "algorithm" => {
                    otp.algorithm = match v.to_ascii_uppercase().as_str() {
                        "SHA1" => Algorithm::Sha1,
                        "SHA256" => Algorithm::Sha256,
                        "SHA512" => Algorithm::Sha512,
                        other => bail!("unsupported OTP algorithm {other:?}"),
                    }
                }
                "digits" => {
                    otp.digits = v
                        .parse()
                        .ok()
                        .filter(|d| (6..=10).contains(d))
                        .context("invalid OTP digits")?
                }
                "period" => {
                    period = v
                        .parse()
                        .ok()
                        .filter(|p| *p > 0)
                        .context("invalid OTP period")?
                }
                "counter" => counter = Some(v.parse().ok().context("invalid HOTP counter")?),
                _ => {}
            }
        }
        otp.kind = match kind.as_str() {
            "totp" => Kind::Totp { period },
            "hotp" => Kind::Hotp {
                counter: counter.context("HOTP URI has no counter")?,
            },
            other => bail!("unknown OTP type {other:?}"),
        };
        otp.secret = secret.context("otpauth URI has no secret")?;
        Ok(otp)
    }

    /// RFC 4226 code for a counter value.
    pub fn code(&self, counter: u64) -> String {
        let msg = counter.to_be_bytes();
        let mac = match self.algorithm {
            Algorithm::Sha1 => hmac::<sha1::Sha1>(&self.secret, &msg),
            Algorithm::Sha256 => hmac::<sha2::Sha256>(&self.secret, &msg),
            Algorithm::Sha512 => hmac::<sha2::Sha512>(&self.secret, &msg),
        };
        let offset = (mac[mac.len() - 1] & 0x0f) as usize;
        let bin =
            u32::from_be_bytes(mac[offset..offset + 4].try_into().expect("4 bytes")) & 0x7fff_ffff;
        let code = u64::from(bin) % 10u64.pow(self.digits);
        format!("{code:0width$}", width = self.digits as usize)
    }

    /// TOTP code at a unix time.
    pub fn code_at(&self, unix_time: u64, period: u64) -> String {
        self.code(unix_time / period)
    }

    pub fn now(&self, period: u64) -> (String, u64) {
        let t = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        (self.code_at(t, period), period - t % period)
    }
}

fn otp_line(contents: &str) -> Option<&str> {
    contents
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("otpauth://"))
}

/// The entry with the first otpauth URI's `counter` parameter set to `counter`,
/// everything else byte-for-byte unchanged.
pub fn with_counter(contents: &str, counter: u64) -> String {
    let mut done = false;
    let mut out = String::with_capacity(contents.len() + 2);
    for line in contents.split_inclusive('\n') {
        if !done && line.trim_start().starts_with("otpauth://") {
            done = true;
            let (body, newline) = match line.strip_suffix('\n') {
                Some(b) => (b, "\n"),
                None => (line, ""),
            };
            let (base, query) = body.split_once('?').unwrap_or((body, ""));
            let params: Vec<String> = query
                .split('&')
                .map(|p| match p.split_once('=') {
                    Some((k, _)) if k.eq_ignore_ascii_case("counter") => format!("{k}={counter}"),
                    _ => p.to_string(),
                })
                .collect();
            out.push_str(&format!("{base}?{}{newline}", params.join("&")));
        } else {
            out.push_str(line);
        }
    }
    out
}

fn hmac<D: EagerHash>(key: &[u8], msg: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut m = <Hmac<D> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(msg);
    Zeroizing::new(m.finalize().into_bytes().to_vec())
}

fn decode_base32(s: &str) -> Result<Zeroizing<Vec<u8>>> {
    let cleaned: String = s
        .replace("%20", "")
        .replace("%3D", "")
        .chars()
        .filter(|c| !matches!(c, ' ' | '-' | '='))
        .map(|c| c.to_ascii_uppercase())
        .collect();
    data_encoding::BASE32_NOPAD
        .decode(cleaned.as_bytes())
        .map(Zeroizing::new)
        .context("OTP secret is not valid base32")
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 appendix B test vectors.
    #[test]
    fn rfc6238_vectors() {
        let cases = [
            ("SHA1", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 59, "94287082"),
            (
                "SHA1",
                "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                1111111109,
                "07081804",
            ),
            (
                "SHA256",
                "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA",
                59,
                "46119246",
            ),
            (
                "SHA512",
                "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA",
                20000000000,
                "47863826",
            ),
        ];
        for (alg, secret, t, want) in cases {
            let uri = format!("otpauth://totp/test?secret={secret}&algorithm={alg}&digits=8");
            assert_eq!(
                Otp::parse(&uri).unwrap().code_at(t, 30),
                want,
                "{alg} at {t}"
            );
        }
    }

    // RFC 4226 appendix D test vectors (secret "12345678901234567890").
    #[test]
    fn rfc4226_vectors() {
        let otp = Otp::parse("otpauth://hotp/t?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=0")
            .unwrap();
        assert_eq!(otp.kind, Kind::Hotp { counter: 0 });
        let want = ["755224", "287082", "359152", "969429", "338314", "254676"];
        for (counter, code) in want.iter().enumerate() {
            assert_eq!(otp.code(counter as u64), *code);
        }
    }

    #[test]
    fn finds_uri_in_entry_with_defaults() {
        let t = Otp::from_entry(
            "hunter2\nuser: me\notpauth://totp/Ex:me?secret=jbsw y3dp ehpk 3pxp&issuer=Ex\n",
        )
        .unwrap();
        assert_eq!((t.digits, &t.kind), (6, &Kind::Totp { period: 30 }));
        assert_eq!(t.algorithm, Algorithm::Sha1);
        assert!(Otp::from_entry("no otp here").is_err());
        assert!(Otp::parse("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP").is_err());
    }

    #[test]
    fn rewrites_only_the_counter() {
        let entry =
            "pw\nnote: a&counter=1\notpauth://hotp/Ex:me?secret=JBSW&counter=7&issuer=Ex\ntail";
        assert_eq!(
            with_counter(entry, 8),
            "pw\nnote: a&counter=1\notpauth://hotp/Ex:me?secret=JBSW&counter=8&issuer=Ex\ntail"
        );
    }
}
