use anyhow::{Result, ensure};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{pattern::SuffixPattern, sequence::CandidateStream};

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Session {
    pub schema_version: u32,
    pub sequence_version: String,
    pub id: String,
    key: [u8; 32],
    pub next_index: u64,
    #[serde(default)]
    pub found_index: Option<u64>,
    pub target_suffix: String,
}

impl Session {
    pub fn new(target: &str) -> Result<Self> {
        SuffixPattern::new(target)?;
        let mut key = [0; 32];
        let mut id = [0; 16];
        OsRng.try_fill_bytes(&mut key)?;
        OsRng.try_fill_bytes(&mut id)?;
        use std::fmt::Write;
        let mut name = String::with_capacity(32);
        for byte in id {
            write!(name, "{byte:02x}")?;
        }
        Ok(Self {
            schema_version: 1,
            sequence_version: "chacha20-rand_chacha-0.3-v1".into(),
            id: name,
            key,
            next_index: 0,
            found_index: None,
            target_suffix: target.into(),
        })
    }

    pub fn validate_target(&self, target: &str) -> Result<()> {
        ensure!(
            self.schema_version == 1 && self.sequence_version == "chacha20-rand_chacha-0.3-v1",
            "Неподдерживаемая версия последовательности"
        );
        ensure!(
            self.id.len() == 32 && self.id.bytes().all(|b| b.is_ascii_hexdigit()),
            "Повреждён идентификатор сессии"
        );
        SuffixPattern::new(&self.target_suffix)?;
        ensure!(
            target == self.target_suffix,
            "Цель отличается от сохранённой; используйте отдельный каталог сессии"
        );
        Ok(())
    }

    pub fn stream(&self) -> CandidateStream {
        CandidateStream::new(self.key)
    }
}
