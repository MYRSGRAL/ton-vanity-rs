//! Публичные фикстуры: bip39, ed25519-hd-key и @ton/ton WalletContractV5R1.
//! Источник: read-only TON-Vanity-W5-Windows/node_modules, 2026-10-21.
use brut_wallet::{
    crypto::{address_from_public, derive_private, derive_wallet},
    pattern::SuffixPattern,
};

fn decode<const N: usize>(s: &str) -> [u8; N] {
    assert_eq!(s.len(), N * 2);
    std::array::from_fn(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
}

#[test]
fn sdk_bip39_slip10_w5_vectors() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/crypto-vectors.json")).unwrap();
    for vector in vectors.as_array().unwrap() {
        let text = |key: &str| vector[key].as_str().unwrap();
        let wallet = derive_wallet(&decode(text("entropy"))).unwrap();
        assert_eq!(wallet.mnemonic.as_str(), text("mnemonic"));
        let mnemonic =
            bip39::Mnemonic::parse_in(bip39::Language::English, text("mnemonic")).unwrap();
        assert_eq!(mnemonic.to_seed_normalized(""), decode::<64>(text("seed")));
        assert_eq!(wallet.address, text("address"));
        let key = derive_private(&decode::<64>(text("seed"))).unwrap();
        assert_eq!(*key, decode::<32>(text("private_key")));
        assert_eq!(
            address_from_public(&decode(text("public_key"))),
            text("address")
        );
    }
}

#[test]
fn suffix_masks_and_case() {
    for (suffix, expected) in [
        ("____", 0xffffff),
        ("_________", (1_u64 << 54) - 1),
        ("__________", (1_u64 << 60) - 1),
    ] {
        let pattern = SuffixPattern::new(suffix).unwrap();
        assert_eq!(pattern.value(), expected);
        assert_eq!(pattern.mask(), expected);
        assert_eq!(pattern.suffix(), suffix);
    }
    let address = "UQC020bHeiUqqyw8BB4EttblmRidKkT_hnINJ-8rZCP0L1Dw";
    let pattern = SuffixPattern::new("L1Dw").unwrap();
    assert!(pattern.matches(address));
    assert!(!SuffixPattern::new("l1dw").unwrap().matches(address));
    assert!(!pattern.matches("L1Dw"));
    for invalid in ["", "abc", "abcdefghijk", "abc=", "абвг", "ab c", "abcd\n"] {
        assert!(SuffixPattern::new(invalid).is_err(), "{invalid:?}");
    }
}

#[test]
fn slip10_rejects_out_of_range_seed() {
    for length in [0, 15, 65, 128] {
        assert!(derive_private(&vec![0; length]).is_err());
    }
}

#[test]
fn suffix_filter_matches_decoded_address_tail() {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let address = "UQC020bHeiUqqyw8BB4EttblmRidKkT_hnINJ-8rZCP0L1Dw";
    let bytes = URL_SAFE_NO_PAD.decode(address).unwrap();
    let ending = u64::from_be_bytes(bytes[bytes.len() - 8..].try_into().unwrap());
    for length in [4, 9, 10] {
        let pattern = SuffixPattern::new(&address[address.len() - length..]).unwrap();
        assert_eq!(ending & pattern.mask(), pattern.value());
        assert!(pattern.matches(address));
    }
}
