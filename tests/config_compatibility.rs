use brut_wallet::config::Config;

#[test]
fn legacy_watch_settings_do_not_block_ton_search_or_rewrite_config() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    let original = "target_suffix = 'cafe'\nbatch_size = 128\n\
        [watch]\nenabled = true\nmax_concurrency = 0\n\
        [[watch.accounts]]\nnetwork = 'obsolete'\nendpoint = 'removed-provider'\n";
    std::fs::write(&path, original).unwrap();

    let config = Config::load(&path).unwrap();

    assert_eq!(config.target_suffix, "cafe");
    assert_eq!(config.batch_size, 128);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
    assert!(!toml::to_string(&config).unwrap().contains("watch"));
}

#[test]
fn legacy_watch_settings_do_not_hide_invalid_generator_settings() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");

    for invalid in [
        "target_sufix = 'cafe'",
        "batch_size = 1",
        "target_suffix = '!' ",
    ] {
        std::fs::write(&path, format!("{invalid}\n[watch]\nenabled = true\n")).unwrap();
        assert!(
            Config::load(&path).is_err(),
            "Приняты неверные настройки: {invalid}"
        );
    }
}
