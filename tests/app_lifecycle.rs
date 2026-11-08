use brut_wallet::{
    app::{commit_batch, completed_result},
    config::Config,
    crypto::derive_wallet,
    session::Session,
    storage,
};

fn fixture() -> (Session, Config, [[u8; 32]; 1]) {
    let mut session = Session::new("abcd").unwrap();
    let mut entropy = [[0; 32]; 1];
    session.stream().fill(0, &mut entropy).unwrap();
    let wallet = derive_wallet(&entropy[0]).unwrap();
    session.target_suffix = wallet.address[44..].to_string();
    let config = Config {
        target_suffix: session.target_suffix.clone(),
        ..Config::default()
    };
    (session, config, entropy)
}

#[test]
fn result_precedes_checkpoint_and_replay_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let (mut session, config, entropy) = fixture();
    commit_batch(dir.path(), &config, &mut session, 0, &entropy, &[0]).unwrap();
    let before = std::fs::read(dir.path().join("wallets.txt")).unwrap();
    let record = storage::load_wallets(dir.path()).unwrap().pop().unwrap();
    assert_eq!(record.address, derive_wallet(&entropy[0]).unwrap().address);
    assert!(String::from_utf8_lossy(&before).contains(&record.words));
    let recovered = storage::load_session(dir.path()).unwrap().unwrap();
    assert_eq!(recovered.next_index, 1);
    assert_eq!(recovered.found_index, Some(0));
    session.next_index = 0;
    commit_batch(dir.path(), &config, &mut session, 0, &entropy, &[0]).unwrap();
    assert_eq!(
        before,
        std::fs::read(dir.path().join("wallets.txt")).unwrap()
    );
    assert!(!dir.path().join("master-key.bin").exists());
}

#[test]
fn output_failure_does_not_advance_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let (mut session, config, entropy) = fixture();
    std::fs::write(dir.path().join("wallets.txt"), "неполная запись").unwrap();
    assert!(commit_batch(dir.path(), &config, &mut session, 0, &entropy, &[0]).is_err());
    assert_eq!(session.next_index, 0);
    assert_eq!(session.found_index, None);
    assert!(!dir.path().join("session.toml").exists());
}

#[test]
fn checkpoint_failure_recovers_found_wallet_and_stops_without_replay() {
    let dir = tempfile::tempdir().unwrap();
    let (mut session, config, entropy) = fixture();
    let original = toml::to_string(&session).unwrap();
    // Портим цель записи после фиксации исходного fixture в памяти.
    std::fs::write(dir.path().join("session.toml"), "поврежденная сессия").unwrap();
    assert!(commit_batch(dir.path(), &config, &mut session, 0, &entropy, &[0]).is_err());
    assert_eq!(session.next_index, 0);
    assert_eq!(session.found_index, None);
    assert_eq!(storage::load_wallets(dir.path()).unwrap().len(), 1);
    std::fs::write(dir.path().join("session.toml"), original).unwrap();
    assert!(
        completed_result(dir.path(), &mut session)
            .unwrap()
            .is_some()
    );
    assert_eq!(session.next_index, 0);
    assert_eq!(session.found_index, Some(0));
}

#[test]
fn already_submitted_batch_preserves_completed_marker() {
    let dir = tempfile::tempdir().unwrap();
    let (mut session, config, entropy) = fixture();
    commit_batch(dir.path(), &config, &mut session, 0, &entropy, &[0]).unwrap();
    let mut second = [[0; 32]; 1];
    session.stream().fill(1, &mut second).unwrap();
    commit_batch(dir.path(), &config, &mut session, 1, &second, &[]).unwrap();
    assert_eq!(session.next_index, 2);
    assert_eq!(session.found_index, Some(0));
}
