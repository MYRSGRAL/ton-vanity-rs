use brut_wallet::{sequence::CandidateStream, session::Session, storage};

#[test]
fn split_resume_has_identical_sequence() {
    let stream = CandidateStream::new([7; 32]);
    let mut whole = [[0; 32]; 19];
    stream.fill(0, &mut whole).unwrap();
    for boundary in [1, 8, 18] {
        let mut split = [[0; 32]; 19];
        stream.fill(0, &mut split[..boundary]).unwrap();
        stream
            .fill(boundary as u64, &mut split[boundary..])
            .unwrap();
        assert_eq!(whole, split);
    }
    assert!(stream.fill(u64::MAX, &mut [[0; 32]; 1]).is_err());
}

#[test]
fn sequence_version_has_fixed_chacha20_vector() {
    let mut output = [[0; 32]; 1];
    CandidateStream::new([0; 32]).fill(0, &mut output).unwrap();
    assert_eq!(
        output[0],
        [
            0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90, 0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86,
            0xbd, 0x28, 0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a, 0xa8, 0x36, 0xef, 0xcc,
            0x8b, 0x77, 0x0d, 0xc7,
        ]
    );
}

#[test]
fn plaintext_state_lock_and_atomic_no_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("session.toml");
    let session = Session::new("abcd").unwrap();
    storage::save_session(dir.path(), &session).unwrap();
    let recovered = storage::load_session(dir.path()).unwrap().unwrap();
    assert_eq!(recovered.next_index, 0);
    assert_eq!(recovered.id, session.id);
    assert!(recovered.validate_target("ABCD").is_err());
    let guard = storage::SessionLock::acquire(dir.path()).unwrap();
    assert!(storage::SessionLock::acquire(dir.path()).is_err());
    drop(guard);
    assert!(storage::SessionLock::acquire(dir.path()).is_ok());
    let before = std::fs::read(&file).unwrap();
    assert!(storage::atomic_write(&file, b"replacement", true).is_err());
    assert_eq!(before, std::fs::read(&file).unwrap());
}

#[test]
fn bounded_read_refuses_oversize_without_reading_all() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("large");
    std::fs::File::create(&file)
        .unwrap()
        .set_len(64 * 1024 * 1024 + 1)
        .unwrap();
    assert!(storage::read_bounded(&file).is_err());
}
