use crate::{
    config::Config,
    crypto::derive_wallet,
    gpu::GpuEngine,
    pattern::SuffixPattern,
    session::Session,
    shutdown::{InterruptAction, Phase, SearchControl, force_exit},
    storage,
    ui::{self, Console, RateWindow},
};
use anyhow::{Context, Result, anyhow, ensure};
use std::{
    collections::VecDeque,
    path::Path,
    sync::{Arc, mpsc},
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub use crate::storage::WalletRecord as FoundWallet;

/// Находки записываются в wallets.txt до подтверждения непрерывного диапазона.
pub fn commit_batch(
    directory: &Path,
    config: &Config,
    session: &mut Session,
    first: u64,
    entropy: &[[u8; 32]],
    hits: &[usize],
) -> Result<usize> {
    session.validate_target(&config.target_suffix)?;
    ensure!(
        first == session.next_index,
        "Нарушен порядок подтверждения пачек"
    );
    let next = first
        .checked_add(u64::try_from(entropy.len())?)
        .context("Исчерпан индекс")?;
    let pattern = SuffixPattern::new(&config.target_suffix)?;
    let mut unique = std::collections::HashSet::new();
    let mut first_found = session.found_index;
    for &offset in hits {
        ensure!(unique.insert(offset), "GPU вернул повторный индекс");
        let candidate = entropy
            .get(offset)
            .context("GPU вернул индекс за границами пачки")?;
        let wallet = derive_wallet(candidate)?;
        ensure!(
            pattern.matches(&wallet.address),
            "Находка не прошла независимую CPU-проверку"
        );
        let index = first
            .checked_add(u64::try_from(offset)?)
            .context("Исчерпан индекс")?;
        let record = FoundWallet {
            schema_version: 1,
            session_id: session.id.clone(),
            index,
            address: wallet.address,
            words: wallet.mnemonic.to_string(),
            mnemonic_type: "BIP39".into(),
            derivation_path: "m/44'/607'/0'".into(),
            wallet_version: "V5R1".into(),
            wallet_id: "0x7fffff11".into(),
            network: "mainnet".into(),
            workchain: 0,
            bip39_passphrase: String::new(),
        };
        storage::append_wallet(directory, &record)?;
        first_found = Some(first_found.map_or(index, |previous| previous.min(index)));
    }
    let previous_index = session.next_index;
    let previous_found = session.found_index;
    session.next_index = next;
    session.found_index = first_found;
    if let Err(error) = storage::save_session(directory, session) {
        session.next_index = previous_index;
        session.found_index = previous_found;
        return Err(error);
    }
    Ok(unique.len())
}

fn validate_session_wallet(session: &Session, record: &FoundWallet) -> Result<()> {
    let mut entropy = Zeroizing::new([[0; 32]; 1]);
    session.stream().fill(record.index, entropy.as_mut())?;
    let expected = derive_wallet(&entropy[0])?;
    ensure!(
        record.session_id == session.id
            && record.address == expected.address
            && record.words == *expected.mnemonic
            && SuffixPattern::new(&session.target_suffix)?.matches(&record.address),
        "Результат не соответствует поисковой сессии"
    );
    Ok(())
}

/// Включает восстановление находки, записанной перед аварией checkpoint.
pub fn completed_result(directory: &Path, session: &mut Session) -> Result<Option<String>> {
    storage::migrate_legacy_wallets(directory, session)?;
    let records = storage::load_wallets(directory)?;
    let earliest = records
        .iter()
        .filter(|record| record.session_id == session.id)
        .min_by_key(|record| record.index);
    if let Some(record) = earliest {
        validate_session_wallet(session, record)?;
        if session.found_index != Some(record.index) {
            let previous = session.found_index;
            session.found_index = Some(record.index);
            if let Err(error) = storage::save_session(directory, session) {
                session.found_index = previous;
                return Err(error);
            }
        }
        return Ok(Some(record.address.clone()));
    }
    ensure!(
        session.found_index.is_none(),
        "Сессия завершена, но в wallets.txt отсутствует её результат; восстановите файл"
    );
    Ok(None)
}

enum Update {
    Device(String),
    Started(Instant),
    Dispatched {
        first: u64,
        count: usize,
    },
    Progress {
        confirmed: u64,
        found: usize,
        at: Instant,
    },
    Found(String),
    Finished(Result<()>),
}

pub fn search(directory: &Path, config: Config, cpu: bool, batch_limit: Option<u64>) -> Result<()> {
    config.validate()?;
    let _lock = storage::SessionLock::acquire(directory)?;
    let mut session = match storage::load_session(directory)? {
        Some(saved) => saved,
        None => {
            let fresh = Session::new(&config.target_suffix)?;
            storage::save_session(directory, &fresh)?;
            fresh
        }
    };
    session.validate_target(&config.target_suffix)?;
    if let Some(address) = completed_result(directory, &mut session)? {
        eprintln!(
            "Поиск уже завершён: {address}\nАдрес и 24 слова: {}",
            directory.join("wallets.txt").display()
        );
        return Ok(());
    }
    // В том числе переводим прочитанную старую сессию в открытый формат с backup.
    storage::save_session(directory, &session)?;
    let initial = session.next_index;
    let stop = Arc::new(SearchControl::default());
    let signal = Arc::clone(&stop);
    ctrlc::set_handler(move || match signal.interrupt_action() {
        InterruptAction::ExitBeforeSearch => force_exit(0),
        InterruptAction::ForceExit => force_exit(130),
        InterruptAction::Drain => {}
    })
    .context("Не удалось установить Ctrl+C")?;
    let (sender, receiver) = mpsc::sync_channel(4);
    let root = directory.to_path_buf();
    let worker_stop = Arc::clone(&stop);
    let started = Instant::now();
    let mut console = Console::default();
    console.message(&format!(
        "TON W5 · окончание «{}» · {}",
        config.target_suffix,
        if cpu {
            "CPU"
        } else {
            "OpenCL, устройство из config.toml"
        }
    ))?;
    console.message(&format!("В среднем одно совпадение на {} адресов. Это статистика, не срок находки.\nCtrl+C — остановить; повторный — принудительный выход.", ui::number(1u64 << (6 * config.target_suffix.len()))))?;
    let worker = thread::spawn(move || {
        let send = |update| {
            sender
                .send(update)
                .map_err(|_| anyhow!("Закрыт канал интерфейса"))
        };
        let result = (|| -> Result<()> {
            let stream = session.stream();
            let pattern = SuffixPattern::new(&config.target_suffix)?;
            if worker_stop.is_stopping() {
                return Ok(());
            }
            let mut engine = if cpu {
                None
            } else {
                Some(GpuEngine::new(config.device_index, config.batch_size)?)
            };
            if let Some(gpu) = &engine {
                send(Update::Device(gpu.device_name().to_string()))?;
            }
            if let Some(gpu) = &mut engine {
                if worker_stop.is_stopping() {
                    return Ok(());
                }
                worker_stop.set_phase(Phase::SelfTesting);
                gpu.self_test()?;
            }
            worker_stop.set_phase(Phase::Searching);
            send(Update::Started(Instant::now()))?;
            let mut submitted = 0u64;
            let mut pending = VecDeque::new();
            let mut reusable = Vec::with_capacity(2);
            let mut next_submit = session.next_index;
            loop {
                while pending.len() < if cpu { 1 } else { 2 }
                    && !worker_stop.is_stopping()
                    && batch_limit.is_none_or(|limit| submitted < limit)
                {
                    let mut entropy = reusable
                        .pop()
                        .unwrap_or_else(|| Zeroizing::new(vec![[0; 32]; config.batch_size]));
                    stream.fill(next_submit, &mut entropy)?;
                    if !worker_stop.try_admit() {
                        break;
                    }
                    let ticket = if let Some(gpu) = &mut engine {
                        Some(gpu.submit(&entropy, &pattern)?)
                    } else {
                        None
                    };
                    let first = next_submit;
                    next_submit = next_submit
                        .checked_add(u64::try_from(entropy.len())?)
                        .context("Исчерпан индекс")?;
                    pending.push_back((first, entropy, ticket));
                    submitted += 1;
                    if submitted == 1 {
                        send(Update::Dispatched {
                            first,
                            count: config.batch_size,
                        })?;
                    }
                }
                let Some((first, mut entropy, ticket)) = pending.pop_front() else {
                    break;
                };
                let hits = if let (Some(gpu), Some(ticket)) = (&mut engine, ticket) {
                    gpu.collect(ticket)?
                } else {
                    let mut hits = Vec::new();
                    for (offset, candidate) in entropy.iter().enumerate() {
                        if pattern.matches(&derive_wallet(candidate)?.address) {
                            hits.push(offset);
                        }
                    }
                    hits
                };
                let found = commit_batch(&root, &config, &mut session, first, &entropy, &hits)?;
                if found > 0 {
                    worker_stop.request_stop();
                    let records = storage::load_wallets(&root)?;
                    for record in records.iter().filter(|record| {
                        record.session_id == session.id
                            && record.index >= first
                            && record.index < session.next_index
                    }) {
                        send(Update::Found(record.address.clone()))?;
                    }
                }
                worker_stop.complete();
                send(Update::Progress {
                    confirmed: session.next_index,
                    found,
                    at: Instant::now(),
                })?;
                // Память двух пачек переиспользуется; секреты очищаются перед возвратом в pool.
                use zeroize::Zeroize;
                entropy.as_mut_slice().as_flattened_mut().zeroize();
                reusable.push(entropy);
            }
            Ok(())
        })();
        if sender.send(Update::Finished(result)).is_err() {
            tracing::error!("Интерфейс завершился до рабочего потока");
        }
    });
    let mut confirmed = initial;
    let mut found = 0;
    let mut searching_since = None;
    let mut rate = None;
    let mut last_print = Instant::now();
    let result = loop {
        match receiver.recv_timeout(Duration::from_millis(250)) {
            Ok(Update::Device(device)) => console.message(&format!("GPU: {device}"))?,
            Ok(Update::Started(at)) => { searching_since = Some(at); rate = Some(RateWindow::new(at, initial)); }
            Ok(Update::Dispatched { first, count }) => {
                // Событие также служит handshake в проверке остановки после отправки.
                if !std::io::IsTerminal::is_terminal(&std::io::stderr()) {
                    console.message(&format!("Первая пачка отправлена: индекс {first}, кандидатов {count}."))?;
                }
            }
            Ok(Update::Found(address)) => console.message(&format!("НАЙДЕН КОШЕЛЁК\nАдрес: {address}\nАдрес и 24 слова записаны в {}\nЗавершаю уже отправленную пачку и останавливаюсь.", directory.join("wallets.txt").display()))?,
            Ok(Update::Progress { confirmed: index, found: count, at }) => {
                confirmed = index; found += count; if let Some(window) = &mut rate { window.observe(at, index); }
            }
            Ok(Update::Finished(result)) => break result,
            Err(mpsc::RecvTimeoutError::Timeout) => {},
            Err(mpsc::RecvTimeoutError::Disconnected) => break Err(anyhow!("Рабочий поток аварийно завершился")),
        }
        if last_print.elapsed() >= Duration::from_secs(1) {
            let elapsed = searching_since.map_or(Duration::ZERO, |at: Instant| at.elapsed());
            let average = if elapsed.is_zero() {
                0.0
            } else {
                (confirmed - initial) as f64 / elapsed.as_secs_f64()
            };
            let window = rate.as_mut().map_or(0.0, |rate| rate.rate(Instant::now()));
            let phase = if stop.is_stopping() {
                "Завершение"
            } else {
                match stop.phase() {
                    Phase::Initializing => {
                        if cpu {
                            "Подготовка CPU"
                        } else {
                            "Подготовка OpenCL"
                        }
                    }
                    Phase::SelfTesting => "Проверка GPU",
                    Phase::Searching => "Поиск",
                }
            };
            console.status(&ui::status(
                phase,
                confirmed - initial,
                found,
                if searching_since.is_some() {
                    elapsed
                } else {
                    started.elapsed()
                },
                window,
                average,
            ))?;
            last_print = Instant::now();
        }
    };
    worker
        .join()
        .map_err(|_| anyhow!("Рабочий поток аварийно завершился"))?;
    console.finish()?;
    result?;
    console.message(&format!(
        "Поиск остановлен. Проверено {} адресов, находок {found}.",
        ui::number(confirmed - initial)
    ))?;
    Ok(())
}
