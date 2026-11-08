use anyhow::{Result, ensure};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Версия 1: ChaCha20Rng 0.3, stream=0, восемь u32 на кандидата.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CandidateStream {
    key: [u8; 32],
}

impl CandidateStream {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    pub fn fill(&self, start: u64, output: &mut [[u8; 32]]) -> Result<()> {
        let length = u64::try_from(output.len())?;
        ensure!(
            start.checked_add(length).is_some(),
            "Исчерпан индекс потока"
        );
        let mut rng = ChaCha20Rng::from_seed(self.key);
        rng.set_stream(0);
        rng.set_word_pos(u128::from(start) * 8);
        rng.fill_bytes(output.as_flattened_mut());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::CandidateStream;
    use rand::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn bulk_fill_preserves_candidate_sequence() {
        for key in [[0; 32], [7; 32], std::array::from_fn(|index| index as u8)] {
            for start in [0, 1, 17, u64::MAX - 1024] {
                for length in [0, 1, 127, 128, 129] {
                    let mut expected = vec![[0; 32]; length];
                    let mut legacy = ChaCha20Rng::from_seed(key);
                    legacy.set_stream(0);
                    legacy.set_word_pos(u128::from(start) * 8);
                    for entropy in &mut expected {
                        legacy.fill_bytes(entropy);
                    }
                    let mut actual = vec![[0; 32]; length];
                    CandidateStream::new(key).fill(start, &mut actual).unwrap();
                    assert_eq!(actual, expected, "start={start}, length={length}");
                }
            }
        }
    }
}
