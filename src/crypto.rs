//! Независимый CPU-эталон BIP39 → SLIP-0010 → Ed25519 → TON W5 mainnet.
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bip39::{Language, Mnemonic};
use ed25519_dalek::SigningKey;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use zeroize::{Zeroize, Zeroizing};

type HmacSha512 = Hmac<Sha512>;

// Hash и depth кода WalletContractV5R1 (@ton/ton 16.3.0), не hash всего BOC.
const W5_CODE_HASH: [u8; 32] = [
    0x20, 0x83, 0x4b, 0x7b, 0x72, 0xb1, 0x12, 0x14, 0x7e, 0x1b, 0x2f, 0xb4, 0x57, 0xb8, 0x4e, 0x74,
    0xd1, 0xa3, 0x0f, 0x04, 0xf7, 0x37, 0xd4, 0xf6, 0x2a, 0x66, 0x8e, 0x95, 0x52, 0xd2, 0xb7, 0x2f,
];

/// Секретная фраза намеренно не поддерживает Debug или Clone.
pub struct Wallet {
    pub address: String,
    pub mnemonic: Zeroizing<String>,
}

pub fn derive_wallet(entropy: &[u8; 32]) -> Result<Wallet> {
    let mnemonic = Mnemonic::from_entropy_in(Language::English, entropy)
        .context("Не удалось создать BIP39-фразу")?;
    let seed = Zeroizing::new(mnemonic.to_seed_normalized(""));
    let private = derive_private(seed.as_ref())?;
    let public = SigningKey::from_bytes(&private).verifying_key().to_bytes();
    Ok(Wallet {
        address: address_from_public(&public),
        mnemonic: Zeroizing::new(mnemonic.to_string()),
    })
}

/// Получает BIP39 seed и выводит Ed25519 seed по m/44'/607'/0'.
pub fn derive_private(seed: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    ensure!(
        (16..=64).contains(&seed.len()),
        "SLIP-0010 seed должен содержать 16–64 байта"
    );
    let mut node = hmac512(b"ed25519 seed", seed)?;
    for index in [44_u32, 607, 0] {
        let mut data = Zeroizing::new([0_u8; 37]);
        data[1..33].copy_from_slice(&node[..32]);
        data[33..].copy_from_slice(&(index | 0x8000_0000).to_be_bytes());
        node = hmac512(&node[32..], data.as_ref())?;
    }
    let mut private = Zeroizing::new([0_u8; 32]);
    private.copy_from_slice(&node[..32]);
    Ok(private)
}

fn hmac512(key: &[u8], data: &[u8]) -> Result<Zeroizing<[u8; 64]>> {
    let mut mac = HmacSha512::new_from_slice(key).context("Не удалось создать HMAC")?;
    mac.update(data);
    let mut output = mac.finalize().into_bytes();
    let result = Zeroizing::new(
        output
            .as_slice()
            .try_into()
            .context("Неверная длина HMAC")?,
    );
    output.as_mut_slice().zeroize();
    Ok(result)
}

pub fn address_from_public(public: &[u8; 32]) -> String {
    // Представление ячейки данных: d1=0, d2=81, 322 бита плюс завершающий бит.
    let mut data = [0_u8; 43];
    data[1] = 81;
    data[2] = 0x80; // is_signature_allowed = 1; seqno = 0.
    let mut fields = [0_u8; 40];
    fields[4..8].copy_from_slice(&0x7fff_ff11_u32.to_be_bytes());
    fields[8..].copy_from_slice(public);
    for (i, byte) in fields.iter().enumerate() {
        data[i + 2] |= byte >> 1;
        data[i + 3] |= (byte & 1) << 7;
    }
    data[42] |= 0x20; // Пустой extensions HashmapE и top-up bit.
    let data_hash = Sha256::digest(data);
    // StateInit: два refs, пять бит 00110 + top-up; depths code=6, data=0.
    let mut state = [0_u8; 71];
    state[..7].copy_from_slice(&[2, 1, 0x34, 0, 6, 0, 0]);
    state[7..39].copy_from_slice(&W5_CODE_HASH);
    state[39..].copy_from_slice(&data_hash);
    let hash = Sha256::digest(state);
    let mut friendly = [0_u8; 36];
    friendly[0] = 0x51; // mainnet, non-bounceable, workchain 0.
    friendly[2..34].copy_from_slice(&hash);
    let crc = crc16(&friendly[..34]);
    friendly[34..].copy_from_slice(&crc.to_be_bytes());
    URL_SAFE_NO_PAD.encode(friendly)
}

fn crc16(bytes: &[u8]) -> u16 {
    bytes.iter().fold(0_u16, |mut crc, byte| {
        crc ^= u16::from(*byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
        crc
    })
}
