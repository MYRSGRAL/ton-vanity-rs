use std::{
    io::{self, IsTerminal, Write},
    path::{Path, PathBuf},
    time::Instant,
};

use anyhow::{Context, Result, ensure};
use brut_wallet::{
    app,
    config::Config,
    crypto::derive_wallet,
    gpu::{self, GpuEngine},
    pattern::SuffixPattern,
    storage,
};
use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    version,
    about = "Генератор собственных TON W5 vanity-кошельков на CPU и OpenCL"
)]
struct Cli {
    /// Каталог конфигурации, сессии и находок; по умолчанию каталог бинарника.
    #[arg(long, global = true)]
    directory: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Показать устройства OpenCL (требуется драйвер).
    Devices,
    /// Самопроверка на публичных фикстурах; GPU только с явным --gpu.
    Check {
        #[arg(long)]
        gpu: bool,
    },
    /// Измерить скорость на публичных данных; CPU только с явным --cpu.
    Benchmark {
        #[arg(long)]
        cpu: bool,
    },
    /// Начать или возобновить поиск; CPU только с явным --cpu.
    Search {
        #[arg(long)]
        cpu: bool,
        /// Остановиться после указанного числа пачек (без ограничения по умолчанию).
        #[arg(long)]
        batches: Option<u64>,
    },
}

fn main() {
    tracing_subscriber::fmt()
        .with_writer(io::stderr)
        .with_ansi(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    if let Err(error) = run() {
        tracing::error!("{error:#}");
        brut_wallet::shutdown::force_exit(1);
    }
    if io::stdout().flush().is_err() || io::stderr().flush().is_err() {
        brut_wallet::shutdown::force_exit(1);
    }
    // run() завершил операции и закрыл файлы. Не вызываем C teardown драйвера.
    brut_wallet::shutdown::force_exit(0);
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let directory = cli.directory.unwrap_or(
        std::env::current_exe()?
            .parent()
            .context("Нет каталога бинарника")?
            .to_path_buf(),
    );
    ensure!(directory.is_dir(), "Каталог данных не существует");
    match cli.command {
        Some(Command::Devices) => {
            for (index, name) in gpu::devices()?.iter().enumerate() {
                writeln!(io::stdout(), "{index}: {name}")?;
            }
        }
        Some(Command::Check { gpu }) => {
            let wallet = derive_wallet(&[0; 32])?;
            ensure!(
                wallet.address == "UQC020bHeiUqqyw8BB4EttblmRidKkT_hnINJ-8rZCP0L1Dw",
                "CPU: адрес не совпал с TON SDK"
            );
            let wallet_ff = derive_wallet(&[255; 32])?;
            ensure!(
                wallet_ff.address == "UQAwdPow8I_FK6qBl1mbQkKabscUp4HoMGLFo9kl2VD74bWz",
                "CPU: FF-адрес не совпал с TON SDK"
            );
            if gpu {
                let config = load_or_default(&directory)?;
                GpuEngine::new(config.device_index, config.batch_size)?.self_test()?;
            }
            writeln!(
                io::stdout(),
                "Проверка пройдена: CPU BIP39/SLIP-0010/TON W5; GPU={gpu}. Публичный адрес: {}",
                wallet.address
            )?;
        }
        Some(Command::Benchmark { cpu }) => {
            let config = load_or_default(&directory)?;
            let pattern = SuffixPattern::new(&config.target_suffix)?;
            let size = if cpu { 128 } else { config.batch_size };
            let mut entropy = Zeroizing::new(vec![[0; 32]; size]);
            brut_wallet::sequence::CandidateStream::new([0; 32]).fill(0, &mut entropy)?;
            let mut engine = if cpu {
                None
            } else {
                Some(GpuEngine::new(config.device_index, size)?)
            };
            if let Some(gpu) = &mut engine {
                gpu.self_test()?;
            }
            let started = Instant::now();
            let checked = if let Some(gpu) = &mut engine {
                let stream = brut_wallet::sequence::CandidateStream::new([0; 32]);
                let mut pending = std::collections::VecDeque::new();
                let rounds = 16u64;
                let mut submitted = 0u64;
                let mut done = 0u64;
                let mut profile = brut_wallet::gpu::GpuProfile::default();
                let mut host_fill = std::time::Duration::ZERO;
                while done < rounds {
                    while pending.len() < 2 && submitted < rounds {
                        let fill_started = Instant::now();
                        stream.fill(submitted * size as u64, &mut entropy)?;
                        host_fill += fill_started.elapsed();
                        pending.push_back(gpu.submit(&entropy, &pattern)?);
                        submitted += 1;
                    }
                    let ticket = pending.pop_front().context("Нарушена очередь benchmark")?;
                    gpu.collect(ticket)?;
                    let last = gpu.last_profile();
                    profile.h2d_ns += last.h2d_ns;
                    profile.bip39_ns += last.bip39_ns;
                    profile.kdf_ns += last.kdf_ns;
                    profile.slip10_ns += last.slip10_ns;
                    profile.ed25519_ns += last.ed25519_ns;
                    profile.filter_ns += last.filter_ns;
                    profile.d2h_ns += last.d2h_ns;
                    done += 1;
                }
                writeln!(
                    io::stdout(),
                    "Конвейер: 2 пачки; измерено {rounds} пачек. CPU-подготовка: {:.2} мс",
                    host_fill.as_secs_f64() * 1000.0
                )?;
                writeln!(
                    io::stdout(),
                    "Сумма этапов GPU, мс: загрузка={:.2}; BIP39={:.2}; PBKDF2={:.2}; SLIP10={:.2}; Ed25519={:.2}; фильтр={:.2}; чтение={:.2}",
                    profile.h2d_ns as f64 / 1e6,
                    profile.bip39_ns as f64 / 1e6,
                    profile.kdf_ns as f64 / 1e6,
                    profile.slip10_ns as f64 / 1e6,
                    profile.ed25519_ns as f64 / 1e6,
                    profile.filter_ns as f64 / 1e6,
                    profile.d2h_ns as f64 / 1e6
                )?;
                rounds * size as u64
            } else {
                for candidate in entropy.iter() {
                    std::hint::black_box(derive_wallet(candidate)?);
                }
                size as u64
            };
            let seconds = started.elapsed().as_secs_f64();
            writeln!(
                io::stdout(),
                "{}: {} адресов за {:.3}с, {}/с. Находки benchmark не сохраняет.",
                if cpu { "CPU" } else { "OpenCL" },
                brut_wallet::ui::number(checked),
                seconds,
                brut_wallet::ui::number((checked as f64 / seconds).round() as u64)
            )?;
        }
        Some(Command::Search { cpu, batches }) => {
            let config = Config::load(&directory.join("config.toml"))?;
            app::search(&directory, config, cpu, batches)?;
        }
        None => interactive(&directory)?,
    }
    Ok(())
}

fn load_or_default(directory: &Path) -> Result<Config> {
    if storage::file_exists(&directory.join("config.toml"))? {
        Config::load(&directory.join("config.toml"))
    } else {
        Ok(Config::default())
    }
}

fn prompt(label: &str) -> Result<String> {
    eprint!("{label}");
    io::stderr().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

fn interactive(directory: &Path) -> Result<()> {
    let file = directory.join("config.toml");
    let config = if storage::file_exists(&file)? {
        Config::load(&file)?
    } else {
        ensure!(
            io::stdin().is_terminal(),
            "Для первого запуска нужен терминал; создайте config.toml или запустите интерактивно"
        );
        let target = prompt("Окончание Base64URL 4–10 символов [myrsgraal]: ")?;
        let target = if target.is_empty() {
            "myrsgraal".into()
        } else {
            target
        };
        let config = Config {
            target_suffix: target,
            ..Config::default()
        };
        config.validate()?;
        storage::atomic_write(&file, toml::to_string_pretty(&config)?.as_bytes(), true)?;
        config
    };
    app::search(directory, config, false, None)
}
