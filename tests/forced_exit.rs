#[cfg(unix)]
#[test]
fn forced_exit_skips_blocked_atexit_and_stops_other_threads() {
    use std::{
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    if std::env::var_os("BRUT_TEST_FORCED_EXIT").is_some() {
        unsafe extern "C" {
            fn atexit(callback: extern "C" fn()) -> i32;
        }
        extern "C" fn blocked_teardown() {
            loop {
                std::thread::sleep(Duration::from_secs(1));
            }
        }
        // Имитирует зарегистрированный драйвером зависающий обработчик завершения.
        assert_eq!(unsafe { atexit(blocked_teardown) }, 0);
        std::thread::spawn(|| {
            loop {
                std::thread::sleep(Duration::from_secs(1));
            }
        });
        brut_wallet::shutdown::force_exit(130);
    }
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "forced_exit_skips_blocked_atexit_and_stops_other_threads",
        ])
        .env("BRUT_TEST_FORCED_EXIT", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert_eq!(status.code(), Some(130));
            break;
        }
        if started.elapsed() > Duration::from_secs(3) {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("Принудительный выход завис в обработчике atexit");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}
