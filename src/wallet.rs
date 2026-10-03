//! BIP39 wallets: a mnemonic from the OS CSPRNG, plus the first receive
//! address for Bitcoin (BIP84, native segwit) and Ethereum (BIP44), derived
//! with BIP32 so any standard wallet shows the same addresses.

use anyhow::{Context, Result, bail};
use hmac::{Hmac, KeyInit, Mac};
use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::sec1::ToSec1Point;
use k256::{FieldBytes, PublicKey, Scalar, SecretKey};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256, Sha512};
use sha3::Keccak256;
use zeroize::Zeroizing;

/// The BIP39 English wordlist (2048 words, 11 bits each), from bitcoin/bips.
const WORDLIST: &str = include_str!("../assets/bip39_english.txt");

pub const BTC_PATH: &str = "m/84'/0'/0'/0/0";
pub const ETH_PATH: &str = "m/44'/60'/0'/0/0";

const HARDENED: u32 = 1 << 31;

pub struct Wallet {
    pub mnemonic: Zeroizing<String>,
    pub btc_address: String,
    pub eth_address: String,
}

impl Wallet {
    /// A new wallet with a `words`-word mnemonic (12 or 24) and no BIP39 passphrase.
    pub fn create(words: usize) -> Result<Wallet> {
        Wallet::from_mnemonic(mnemonic(words)?, "")
    }

    fn from_mnemonic(mnemonic: Zeroizing<String>, passphrase: &str) -> Result<Wallet> {
        let seed = seed(&mnemonic, passphrase);
        let master = ExtendedKey::master(&*seed)?;
        let btc = master.derive(BTC_PATH)?.key.public_key();
        let eth = master.derive(ETH_PATH)?.key.public_key();
        Ok(Wallet {
            mnemonic,
            btc_address: btc_address(&btc)?,
            eth_address: eth_address(&eth),
        })
    }

    /// The store entry: the mnemonic on the first line, then `key: value` fields.
    pub fn entry(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(
            format!(
                "{}\ntype: bip39\nbtc-path: {BTC_PATH}\nbtc-address: {}\neth-path: {ETH_PATH}\neth-address: {}\n",
                *self.mnemonic, self.btc_address, self.eth_address
            )
            .into_bytes(),
        )
    }
}

/// A random mnemonic of 12 (128-bit) or 24 (256-bit) words.
pub fn mnemonic(words: usize) -> Result<Zeroizing<String>> {
    let mut entropy = Zeroizing::new([0u8; 32]);
    let len = match words {
        12 => 16,
        24 => 32,
        _ => bail!("a wallet mnemonic has 12 or 24 words."),
    };
    getrandom::fill(&mut entropy[..len])?;
    Ok(mnemonic_from_entropy(&entropy[..len]))
}

/// Encodes entropy (a multiple of 4 bytes) as BIP39 words: the entropy, then
/// the first ENT/32 bits of its SHA-256, read 11 bits at a time.
fn mnemonic_from_entropy(entropy: &[u8]) -> Zeroizing<String> {
    let words: Vec<&str> = WORDLIST.lines().collect();
    let mut bits = Zeroizing::new(entropy.to_vec());
    bits.push(Sha256::digest(entropy)[0]);
    let count = entropy.len() * 8 * 33 / 32 / 11;
    let mut out = Zeroizing::new(String::new());
    for w in 0..count {
        let index = (w * 11..w * 11 + 11).fold(0, |acc, bit| {
            (acc << 1) | usize::from((bits[bit / 8] >> (7 - bit % 8)) & 1)
        });
        if w > 0 {
            out.push(' ');
        }
        out.push_str(words[index]);
    }
    out
}

/// The 64-byte BIP39 seed. Both inputs must already be NFKD-normalized, which
/// English mnemonics and ASCII passphrases are.
fn seed(mnemonic: &str, passphrase: &str) -> Zeroizing<[u8; 64]> {
    let salt = Zeroizing::new(format!("mnemonic{passphrase}"));
    let mut out = Zeroizing::new([0u8; 64]);
    pbkdf2::pbkdf2_hmac::<Sha512>(mnemonic.as_bytes(), salt.as_bytes(), 2048, &mut *out);
    out
}

/// A BIP32 extended private key.
struct ExtendedKey {
    key: SecretKey,
    chain_code: Zeroizing<[u8; 32]>,
}

impl ExtendedKey {
    fn master(seed: &[u8]) -> Result<ExtendedKey> {
        let i = hmac_sha512(b"Bitcoin seed", &[seed]);
        let key =
            SecretKey::from_slice(&i[..32]).context("the seed gives an invalid master key")?;
        Ok(ExtendedKey::new(key, &i[32..]))
    }

    fn new(key: SecretKey, chain_code: &[u8]) -> ExtendedKey {
        let mut cc = Zeroizing::new([0u8; 32]);
        cc.copy_from_slice(chain_code);
        ExtendedKey {
            key,
            chain_code: cc,
        }
    }

    /// Follows a path like `m/84'/0'/0'/0/0` from this (master) key.
    fn derive(&self, path: &str) -> Result<ExtendedKey> {
        let mut parts = path.split('/');
        if parts.next() != Some("m") {
            bail!("derivation path {path:?} must start with m/");
        }
        let mut key = ExtendedKey::new(self.key.clone(), &*self.chain_code);
        for part in parts {
            let (num, hardened) = match part.strip_suffix('\'') {
                Some(n) => (n, HARDENED),
                None => (part, 0),
            };
            let index: u32 = num.parse().context("bad derivation path")?;
            if index >= HARDENED {
                bail!("bad derivation path {path:?}");
            }
            key = key.child(index | hardened)?;
        }
        Ok(key)
    }

    fn child(&self, index: u32) -> Result<ExtendedKey> {
        let index_bytes = index.to_be_bytes();
        let i = if index >= HARDENED {
            let secret = Zeroizing::new(self.key.to_bytes());
            hmac_sha512(&*self.chain_code, &[&[0], &secret, &index_bytes])
        } else {
            let public = compressed(&self.key.public_key());
            hmac_sha512(&*self.chain_code, &[&public, &index_bytes])
        };
        let tweak = Zeroizing::new(
            Option::<Scalar>::from(Scalar::from_repr(
                FieldBytes::try_from(&i[..32]).expect("32 bytes"),
            ))
            .context("invalid child key; this index cannot be used")?,
        );
        let scalar = Zeroizing::new(*tweak + self.key.to_nonzero_scalar().as_ref());
        let key = Option::<SecretKey>::from(SecretKey::from_scalar(*scalar))
            .context("invalid child key; this index cannot be used")?;
        Ok(ExtendedKey::new(key, &i[32..]))
    }
}

fn hmac_sha512(key: &[u8], parts: &[&[u8]]) -> Zeroizing<[u8; 64]> {
    let mut m =
        <Hmac<Sha512> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    for part in parts {
        m.update(part);
    }
    let mut out = Zeroizing::new([0u8; 64]);
    out.copy_from_slice(&m.finalize().into_bytes());
    out
}

fn compressed(key: &PublicKey) -> Vec<u8> {
    key.as_affine().to_sec1_point(true).as_bytes().to_vec()
}

/// Native segwit (P2WPKH) address: bech32 of RIPEMD160(SHA256(compressed key)).
fn btc_address(key: &PublicKey) -> Result<String> {
    let hash = Ripemd160::digest(Sha256::digest(compressed(key)));
    Ok(bech32::segwit::encode_v0(bech32::hrp::BC, &hash)?)
}

/// The last 20 bytes of Keccak-256 of the uncompressed key, with the EIP-55
/// mixed-case checksum.
fn eth_address(key: &PublicKey) -> String {
    let point = key.as_affine().to_sec1_point(false);
    let hex = data_encoding::HEXLOWER.encode(&Keccak256::digest(&point.as_bytes()[1..])[12..]);
    let check = Keccak256::digest(hex.as_bytes());
    let mixed: String = hex
        .chars()
        .enumerate()
        .map(|(i, c)| {
            let nibble = (check[i / 2] >> if i % 2 == 0 { 4 } else { 0 }) & 0xf;
            if nibble >= 8 {
                c.to_ascii_uppercase()
            } else {
                c
            }
        })
        .collect();
    format!("0x{mixed}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const ABANDON: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn hex(s: &str) -> Vec<u8> {
        data_encoding::HEXLOWER.decode(s.as_bytes()).unwrap()
    }

    #[test]
    fn wordlist_is_the_bip39_english_list() {
        let words: Vec<&str> = WORDLIST.lines().collect();
        assert_eq!(words.len(), 2048);
        assert_eq!((words[0], words[2047]), ("abandon", "zoo"));
    }

    #[test]
    fn mnemonics_match_the_bip39_vectors() {
        // From the reference test vectors (trezor/python-mnemonic vectors.json).
        let cases = [
            ("00000000000000000000000000000000", ABANDON),
            (
                "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
                "legal winner thank year wave sausage worth useful legal winner thank yellow",
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000000000",
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
            ),
            (
                "8080808080808080808080808080808080808080808080808080808080808080",
                "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
            ),
        ];
        for (entropy, words) in cases {
            assert_eq!(*mnemonic_from_entropy(&hex(entropy)), words);
        }
    }

    #[test]
    fn seeds_match_the_bip39_vectors() {
        assert_eq!(
            data_encoding::HEXLOWER.encode(&*seed(ABANDON, "TREZOR")),
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        );
    }

    #[test]
    fn addresses_match_known_wallets() {
        let w = Wallet::from_mnemonic(Zeroizing::new(ABANDON.into()), "").unwrap();
        // The first receive address in BIP84's own test vectors.
        assert_eq!(w.btc_address, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
        assert_eq!(w.eth_address, "0x9858EfFD232B4033E47d90003D41EC34EcaEda94");
    }

    #[test]
    fn random_mnemonics_have_valid_checksums() {
        let words: Vec<&str> = WORDLIST.lines().collect();
        for count in [12, 24] {
            let phrase = mnemonic(count).unwrap();
            let indices: Vec<usize> = phrase
                .split(' ')
                .map(|w| words.iter().position(|l| *l == w).unwrap())
                .collect();
            assert_eq!(indices.len(), count);
            let bits: Vec<u8> = indices
                .iter()
                .flat_map(|i| (0..11).rev().map(move |b| ((i >> b) & 1) as u8))
                .collect();
            let ent = count * 11 * 32 / 33;
            let entropy: Vec<u8> = bits[..ent]
                .chunks(8)
                .map(|c| c.iter().fold(0, |acc, b| (acc << 1) | b))
                .collect();
            assert_eq!(*mnemonic_from_entropy(&entropy), *phrase);
        }
        assert!(mnemonic(18).is_err());
    }
}
