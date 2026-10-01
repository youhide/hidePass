//! TOTP codes (RFC 6238) from `otpauth://totp/...` lines, the format used by
//! pass-otp, so existing entries work without the extension.

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

#[derive(Debug)]
pub struct Totp {
    secret: Zeroizing<Vec<u8>>,
    pub algorithm: Algorithm,
    pub digits: u32,
    pub period: u64,
}

impl Totp {
    /// Finds and parses the first otpauth URI in an entry.
    pub fn from_entry(contents: &str) -> Result<Totp> {
        let line = contents
            .lines()
            .map(str::trim)
            .find(|l| l.starts_with("otpauth://"))
            .context("no otpauth:// URI found in this entry.")?;
        Totp::parse(line)
    }

    pub fn parse(uri: &str) -> Result<Totp> {
        let rest = uri
            .strip_prefix("otpauth://")
            .context("not an otpauth:// URI")?;
        let (kind, rest) = rest.split_once('/').context("malformed otpauth URI")?;
        match kind.to_ascii_lowercase().as_str() {
            "totp" => {}
            "hotp" => bail!("HOTP entries are not supported yet, only TOTP."),
            other => bail!("unknown OTP type {other:?}"),
        }
        let query = rest.split_once('?').map(|(_, q)| q).unwrap_or("");
        let mut secret = None;
        let mut totp = Totp {
            secret: Zeroizing::new(Vec::new()),
            algorithm: Algorithm::Sha1,
            digits: 6,
            period: 30,
        };
        for pair in query.split('&') {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            match k.to_ascii_lowercase().as_str() {
                "secret" => secret = Some(decode_base32(v)?),
                "algorithm" => {
                    totp.algorithm = match v.to_ascii_uppercase().as_str() {
                        "SHA1" => Algorithm::Sha1,
                        "SHA256" => Algorithm::Sha256,
                        "SHA512" => Algorithm::Sha512,
                        other => bail!("unsupported OTP algorithm {other:?}"),
                    }
                }
                "digits" => {
                    totp.digits = v
                        .parse()
                        .ok()
                        .filter(|d| (6..=10).contains(d))
                        .context("invalid OTP digits")?
                }
                "period" => {
                    totp.period = v
                        .parse()
                        .ok()
                        .filter(|p| *p > 0)
                        .context("invalid OTP period")?
                }
                _ => {}
            }
        }
        totp.secret = secret.context("otpauth URI has no secret")?;
        Ok(totp)
    }

    pub fn code_at(&self, unix_time: u64) -> String {
        let counter = (unix_time / self.period).to_be_bytes();
        let mac = match self.algorithm {
            Algorithm::Sha1 => hmac::<sha1::Sha1>(&self.secret, &counter),
            Algorithm::Sha256 => hmac::<sha2::Sha256>(&self.secret, &counter),
            Algorithm::Sha512 => hmac::<sha2::Sha512>(&self.secret, &counter),
        };
        let offset = (mac[mac.len() - 1] & 0x0f) as usize;
        let bin =
            u32::from_be_bytes(mac[offset..offset + 4].try_into().expect("4 bytes")) & 0x7fff_ffff;
        let code = u64::from(bin) % 10u64.pow(self.digits);
        format!("{code:0width$}", width = self.digits as usize)
    }

    pub fn now(&self) -> (String, u64) {
        let t = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        (self.code_at(t), self.period - t % self.period)
    }
}

fn hmac<D: EagerHash>(key: &[u8], msg: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut m = <Hmac<D> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(msg);
    Zeroizing::new(m.finalize().into_bytes().to_vec())
}

fn decode_base32(s: &str) -> Result<Zeroizing<Vec<u8>>> {
    let cleaned: String = s
        .chars()
        .filter(|c| !matches!(c, ' ' | '-' | '='))
        .map(|c| c.to_ascii_uppercase())
        .collect();
    let cleaned = cleaned.replace("%3D", "");
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
            assert_eq!(Totp::parse(&uri).unwrap().code_at(t), want, "{alg} at {t}");
        }
    }

    #[test]
    fn finds_uri_in_entry_with_defaults() {
        let t = Totp::from_entry(
            "hunter2\nuser: me\notpauth://totp/Ex:me?secret=jbsw y3dp ehpk 3pxp&issuer=Ex\n",
        )
        .unwrap();
        assert_eq!((t.digits, t.period), (6, 30));
        assert_eq!(t.algorithm, Algorithm::Sha1);
        assert!(Totp::from_entry("no otp here").is_err());
        assert!(Totp::parse("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1").is_err());
    }
}
