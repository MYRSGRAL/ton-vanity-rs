use brut_wallet::{
    crypto::derive_wallet,
    session::Session,
    storage::{self, WalletRecord},
};

fn wallet(session: &Session, index: u64) -> WalletRecord {
    let derived = derive_wallet(&[0; 32]).unwrap();
    WalletRecord {
        schema_version: 1,
        session_id: session.id.clone(),
        index,
        address: derived.address.clone(),
        words: derived.mnemonic.to_string(),
        mnemonic_type: "BIP39".into(),
        derivation_path: "m/44'/607'/0'".into(),
        wallet_version: "V5R1".into(),
        wallet_id: "0x7fffff11".into(),
        network: "mainnet".into(),
        workchain: 0,
        bip39_passphrase: String::new(),
    }
}

#[test]
fn plaintext_roundtrip_deduplicates_without_a_master_key() {
    let dir = tempfile::tempdir().unwrap();
    let mut session = Session::new("abcd").unwrap();
    session.next_index = 10;
    session.found_index = Some(7);
    storage::save_session(dir.path(), &session).unwrap();
    let recovered = storage::load_session(dir.path()).unwrap().unwrap();
    assert_eq!(recovered.next_index, 10);
    assert_eq!(recovered.found_index, Some(7));
    assert!(!dir.path().join("master-key.bin").exists());
    let found = wallet(&session, 7);
    assert!(storage::append_wallet(dir.path(), &found).unwrap());
    let before = std::fs::read(dir.path().join("wallets.txt")).unwrap();
    assert!(String::from_utf8_lossy(&before).contains(&found.words));
    assert!(!storage::append_wallet(dir.path(), &found).unwrap());
    assert_eq!(storage::load_wallets(dir.path()).unwrap().len(), 1);
    let mut conflicting = wallet(&session, 7);
    let other = derive_wallet(&[1; 32]).unwrap();
    conflicting.address = other.address.clone();
    conflicting.words = other.mnemonic.to_string();
    assert!(storage::append_wallet(dir.path(), &conflicting).is_err());
    assert_eq!(
        before,
        std::fs::read(dir.path().join("wallets.txt")).unwrap()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for file in ["session.toml", "wallets.txt"] {
            assert_eq!(
                std::fs::metadata(dir.path().join(file))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }
}

#[test]
fn malformed_existing_files_are_preserved() {
    let dir = tempfile::tempdir().unwrap();
    let session = Session::new("abcd").unwrap();
    for file in ["wallets.txt", "session.toml"] {
        std::fs::write(dir.path().join(file), "неполная запись").unwrap();
    }
    assert!(storage::append_wallet(dir.path(), &wallet(&session, 0)).is_err());
    assert!(storage::save_session(dir.path(), &session).is_err());
    for file in ["wallets.txt", "session.toml"] {
        assert_eq!(
            std::fs::read_to_string(dir.path().join(file)).unwrap(),
            "неполная запись"
        );
    }
}

#[test]
fn truncated_block_and_pending_temporary_file_do_not_replace_durable_wallets() {
    let dir = tempfile::tempdir().unwrap();
    let session = Session::new("abcd").unwrap();
    let found = wallet(&session, 0);
    storage::append_wallet(dir.path(), &found).unwrap();
    let file = dir.path().join("wallets.txt");
    let complete = std::fs::read_to_string(&file).unwrap();
    // Незавершённый временный файл после прерывания не является checkpoint.
    std::fs::write(dir.path().join(".tmp-interrupted"), "частичная запись").unwrap();
    assert_eq!(storage::load_wallets(dir.path()).unwrap().len(), 1);
    let truncated = complete.replace("[/TON-W5]", "");
    std::fs::write(&file, &truncated).unwrap();
    assert!(storage::append_wallet(dir.path(), &wallet(&session, 1)).is_err());
    assert_eq!(std::fs::read_to_string(&file).unwrap(), truncated);
}
