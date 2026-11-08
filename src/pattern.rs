//! Регистрозависимый Base64URL-суффикс, помещающийся в 64-битный фильтр.
use anyhow::{Result, ensure};

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SuffixPattern {
    suffix: String,
    value: u64,
    mask: u64,
}

impl SuffixPattern {
    pub fn new(suffix: &str) -> Result<Self> {
        ensure!(
            (4..=10).contains(&suffix.len()),
            "Окончание должно содержать 4–10 символов Base64URL"
        );
        let mut value = 0_u64;
        for byte in suffix.bytes() {
            let digit = ALPHABET
                .iter()
                .position(|candidate| *candidate == byte)
                .ok_or_else(|| anyhow::anyhow!("Допустимы только A–Z, a–z, 0–9, _ и -"))?;
            value = (value << 6) | digit as u64;
        }
        Ok(Self {
            suffix: suffix.to_owned(),
            value,
            mask: (1_u64 << (6 * suffix.len())) - 1,
        })
    }

    pub fn value(&self) -> u64 {
        self.value
    }
    pub fn mask(&self) -> u64 {
        self.mask
    }
    pub fn suffix(&self) -> &str {
        &self.suffix
    }

    pub fn matches(&self, address: &str) -> bool {
        address.len() == 48
            && address.starts_with("UQ")
            && matches!(address.as_bytes()[2], b'A'..=b'D')
            && address.bytes().all(|byte| ALPHABET.contains(&byte))
            && address.ends_with(&self.suffix)
    }
}
