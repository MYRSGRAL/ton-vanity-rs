use base64::{Engine, engine::general_purpose::STANDARD};
use brut_wallet::{crypto::derive_wallet, session::Session, storage};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use serde::Serialize;

const PUBLIC_KEY: [u8; 32] = [23; 32];

#[derive(Serialize)]
struct Envelope {
    schema_version: u32,
    nonce: String,
    ciphertext: String,
}

fn envelope(plaintext: &str) -> String {
    let nonce = [5; 24];
    let cipher = XChaCha20Poly1305::new_from_slice(&PUBLIC_KEY).unwrap();
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_bytes(),
                aad: b"brut-wallet/envelope/v2",
            },
        )
        .unwrap();
    toml::to_string(&Envelope {
        schema_version: 2,
        nonce: STANDARD.encode(nonce),
        ciphertext: STANDARD.encode(ciphertext),
    })
    .unwrap()
}

fn key(directory: &std::path::Path) {
    storage::atomic_write(&directory.join("master-key.bin"), &PUBLIC_KEY, true).unwrap();
}

#[test]
fn legacy_session_is_read_only_until_backed_up() {
    let dir = tempfile::tempdir().unwrap();
    key(dir.path());
    let state = Session::new("myrs").unwrap();
    // В 0.2 поле found_index отсутствовало.
    let plain = toml::to_string(&state).unwrap();
    let encrypted = envelope(&plain);
    let file = dir.path().join("session.toml");
    std::fs::write(&file, &encrypted).unwrap();
    let recovered = storage::load_session(dir.path()).unwrap().unwrap();
    assert_eq!(recovered.id, state.id);
    assert_eq!(recovered.found_index, None);
    assert_eq!(std::fs::read_to_string(&file).unwrap(), encrypted);
    storage::save_session(dir.path(), &recovered).unwrap();
    assert_eq!(
        std::fs::read_to_string(dir.path().join("session-v0.2.backup.toml")).unwrap(),
        encrypted
    );
    assert!(
        std::fs::read_to_string(file)
            .unwrap()
            .contains("sequence_version")
    );
    assert_eq!(
        std::fs::read(dir.path().join("master-key.bin")).unwrap(),
        PUBLIC_KEY
    );
}

#[test]
fn missing_invalid_or_wrong_key_never_replaces_old_session() {
    let dir = tempfile::tempdir().unwrap();
    let session = Session::new("abcd").unwrap();
    let encrypted = envelope(&toml::to_string(&session).unwrap());
    let file = dir.path().join("session.toml");
    std::fs::write(&file, &encrypted).unwrap();
    assert!(storage::load_session(dir.path()).is_err());
    assert!(!dir.path().join("master-key.bin").exists());
    storage::atomic_write(&dir.path().join("master-key.bin"), &[8; 31], true).unwrap();
    assert!(storage::save_session(dir.path(), &session).is_err());
    storage::atomic_write(&dir.path().join("master-key.bin"), &[8; 32], false).unwrap();
    assert!(storage::load_session(dir.path()).is_err());
    assert_eq!(std::fs::read_to_string(file).unwrap(), encrypted);
    assert!(!dir.path().join("session-v0.2.backup.toml").exists());
}

#[test]
fn conflicting_backup_prevents_overwriting_legacy_session() {
    let dir = tempfile::tempdir().unwrap();
    key(dir.path());
    let session = Session::new("abcd").unwrap();
    let encrypted = envelope(&toml::to_string(&session).unwrap());
    let file = dir.path().join("session.toml");
    std::fs::write(&file, &encrypted).unwrap();
    std::fs::write(dir.path().join("session-v0.2.backup.toml"), "другая копия").unwrap();
    assert!(storage::save_session(dir.path(), &session).is_err());
    assert_eq!(std::fs::read_to_string(file).unwrap(), encrypted);
}

#[test]
fn password_v1_is_preserved_without_creating_a_new_key() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("session.toml");
    let legacy = "schema_version = 1\nciphertext = 'legacy-public-fixture'\n";
    std::fs::write(&file, legacy).unwrap();
    assert!(storage::load_session(dir.path()).is_err());
    assert_eq!(std::fs::read_to_string(file).unwrap(), legacy);
    assert!(!dir.path().join("master-key.bin").exists());
}

#[test]
fn legacy_wallet_migration_validates_and_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    key(dir.path());
    let session = Session::new("abcd").unwrap();
    let derived = derive_wallet(&[0; 32]).unwrap();
    let old_wallet = format!(
        r#"schema_version = 1
session_id = "{}"
index = 3
address = "{}"
words = "{}"
mnemonic_type = "BIP39"
derivation_path = "m/44'/607'/0'"
wallet_version = "V5R1"
wallet_id = "0x7fffff11"
network = "mainnet"
workchain = 0
bip39_passphrase = ""
"#,
        session.id,
        derived.address,
        derived.mnemonic.as_str()
    );
    let encrypted = envelope(&old_wallet);
    let path = dir.path().join(format!("wallet-{}-3.toml", session.id));
    std::fs::write(&path, &encrypted).unwrap();
    // Другие сессии не загружаются и не требуют корректного содержимого.
    std::fs::write(
        dir.path()
            .join("wallet-ffffffffffffffffffffffffffffffff-8.toml"),
        "не эта сессия",
    )
    .unwrap();
    assert_eq!(
        storage::migrate_legacy_wallets(dir.path(), &session).unwrap(),
        1
    );
    assert_eq!(
        storage::migrate_legacy_wallets(dir.path(), &session).unwrap(),
        0
    );
    let recovered = storage::load_wallets(dir.path()).unwrap();
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0].words, *derived.mnemonic);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), encrypted);
    let invalid_path = dir.path().join(format!("wallet-{}-4.toml", session.id));
    let next_wallet = old_wallet.replace("index = 3", "index = 4");
    let invalid = envelope(&next_wallet.replace("V5R1", "V4R2"));
    std::fs::write(&invalid_path, invalid).unwrap();
    let before = std::fs::read(dir.path().join("wallets.txt")).unwrap();
    assert!(storage::migrate_legacy_wallets(dir.path(), &session).is_err());
    assert_eq!(
        before,
        std::fs::read(dir.path().join("wallets.txt")).unwrap()
    );
    let other = derive_wallet(&[1; 32]).unwrap();
    std::fs::write(
        &invalid_path,
        envelope(&next_wallet.replace(&derived.address, &other.address)),
    )
    .unwrap();
    assert!(storage::migrate_legacy_wallets(dir.path(), &session).is_err());
    assert_eq!(
        before,
        std::fs::read(dir.path().join("wallets.txt")).unwrap()
    );
    std::fs::remove_file(invalid_path).unwrap();
    std::fs::remove_file(dir.path().join("master-key.bin")).unwrap();
    assert_eq!(
        storage::migrate_legacy_wallets(dir.path(), &session).unwrap(),
        0
    );
}
