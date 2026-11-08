use std::process::{Command, Stdio};

fn search(directory: &std::path::Path) -> std::process::Output {
    let child = Command::new(env!("CARGO_BIN_EXE_brut-wallet"))
        .args([
            "--directory",
            directory.to_str().unwrap(),
            "search",
            "--cpu",
            "--batches",
            "0",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn non_tty_start_resume_and_corruption() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("config.toml"),
        "schema_version=1\ntarget_suffix='abcd'\nbatch_size=128\npipeline_depth=2\n",
    )
    .unwrap();
    let first = search(dir.path());
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(search(dir.path()).status.success());
    let raw = std::fs::read_to_string(dir.path().join("session.toml")).unwrap();
    assert!(raw.contains("sequence_version"));
    assert!(!raw.contains("ciphertext"));
    assert!(!dir.path().join("master-key.bin").exists());
    for output in [&first.stdout, &first.stderr] {
        assert!(!output.contains(&0x1b));
        assert!(
            !String::from_utf8_lossy(output)
                .to_lowercase()
                .contains("пароль")
        );
    }
    std::fs::write(dir.path().join("session.toml"), "broken").unwrap();
    assert!(!search(dir.path()).status.success());
}

#[test]
fn public_check_is_cpu_only() {
    let output = Command::new(env!("CARGO_BIN_EXE_brut-wallet"))
        .arg("check")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("GPU=false"));
}

#[cfg(unix)]
#[test]
fn ctrl_c_drains_one_cpu_batch_and_double_signal_is_explicit_abort() {
    use std::io::{BufRead, BufReader};
    for double in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        // Большая CPU-пачка обеспечивает время для обоих сигналов без GPU.
        let batch = if double { 65536 } else { 128 };
        std::fs::write(
            dir.path().join("config.toml"),
            format!("target_suffix='abcd'\nbatch_size={batch}\n"),
        )
        .unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_brut-wallet"));
        command.args([
            "--directory",
            dir.path().to_str().unwrap(),
            "search",
            "--cpu",
        ]);
        if !double {
            command.args(["--batches", "1"]);
        }
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stderr = child.stderr.take().unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                if sender.send(line).is_err() {
                    return;
                }
            }
        });
        let startup_deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let remaining = startup_deadline.saturating_duration_since(std::time::Instant::now());
            let next = if remaining.is_zero() {
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            } else {
                receiver.recv_timeout(remaining)
            };
            match next {
                Ok(Ok(line)) if line.contains("Первая пачка отправлена:") => {
                    break;
                }
                Ok(Ok(_)) => {}
                other => {
                    child.kill().unwrap();
                    child.wait().unwrap();
                    reader.join().unwrap();
                    panic!("Не получена отправка первой пачки: {other:?}");
                }
            }
        }
        let signal = || {
            assert!(
                Command::new("kill")
                    .args(["-INT", &child.id().to_string()])
                    .status()
                    .unwrap()
                    .success()
            );
        };
        signal();
        if double {
            std::thread::sleep(std::time::Duration::from_millis(50));
            signal();
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                reader.join().unwrap();
                panic!("Остановка превысила deadline; дочерний процесс завершён");
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        reader.join().unwrap();
        if double {
            assert_eq!(status.code(), Some(130));
        } else {
            assert!(status.success());
        }
        let session = brut_wallet::storage::load_session(dir.path())
            .unwrap()
            .unwrap();
        assert_eq!(session.next_index, if double { 0 } else { 128 });
    }
}

#[test]
fn first_hit_stops_search_and_restart_only_shows_the_result() {
    use brut_wallet::{config::Config, crypto::derive_wallet, session::Session, storage};
    let dir = tempfile::tempdir().unwrap();
    let mut session = Session::new("abcd").unwrap();
    let mut entropy = [[0; 32]; 1];
    session.stream().fill(0, &mut entropy).unwrap();
    let expected = derive_wallet(&entropy[0]).unwrap();
    session.target_suffix = expected.address[44..].to_string();
    let config = Config {
        target_suffix: session.target_suffix.clone(),
        batch_size: 128,
        ..Config::default()
    };
    std::fs::write(
        dir.path().join("config.toml"),
        toml::to_string(&config).unwrap(),
    )
    .unwrap();
    storage::save_session(dir.path(), &session).unwrap();
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_brut-wallet"))
            .args([
                "--directory",
                dir.path().to_str().unwrap(),
                "search",
                "--cpu",
                "--batches",
                "5",
            ])
            .stdin(Stdio::null())
            .output()
            .unwrap()
    };
    let first = run();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let saved = storage::load_session(dir.path()).unwrap().unwrap();
    assert_eq!(saved.next_index, 128);
    assert_eq!(saved.found_index, Some(0));
    let before = std::fs::read(dir.path().join("wallets.txt")).unwrap();
    assert!(String::from_utf8_lossy(&before).contains(expected.mnemonic.as_str()));
    assert!(String::from_utf8_lossy(&first.stderr).contains("НАЙДЕН КОШЕЛЁК"));
    let resumed = run();
    assert!(resumed.status.success());
    assert!(String::from_utf8_lossy(&resumed.stderr).contains("уже завершён"));
    assert_eq!(
        before,
        std::fs::read(dir.path().join("wallets.txt")).unwrap()
    );
    assert_eq!(
        storage::load_session(dir.path())
            .unwrap()
            .unwrap()
            .next_index,
        128
    );
}
