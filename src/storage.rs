use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
};

use anyhow::{Context, Result, anyhow, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{crypto::derive_wallet, session::Session};

const MAX_FILE: u64 = 128 * 1024;
const MAX_WALLETS_FILE: u64 = 64 * 1024 * 1024;
const AAD: &[u8] = b"brut-wallet/envelope/v2";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema_version: u32,
    nonce: String,
    ciphertext: String,
}

pub struct SessionLock(File);

impl SessionLock {
    pub fn acquire(directory: &Path) -> Result<Self> {
        let file = private_open(&directory.join("session.lock"))?;
        file.try_lock()
            .map_err(|_| anyhow!("Сессия уже занята другим процессом"))?;
        Ok(Self(file))
    }
}

impl Drop for SessionLock {
    fn drop(&mut self) {
        // Закрытие файла тоже освобождает OS lock; ошибка не влияет на данные.
        if let Err(error) = self.0.unlock() {
            tracing::warn!(%error, "Не удалось явно освободить блокировку");
        }
    }
}

fn private_open(file: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(file)
        .context("Не удалось открыть приватный файл")
}

pub fn read_bounded(file: &Path) -> Result<Vec<u8>> {
    read_with_limit(file, MAX_FILE)
}

fn read_with_limit(file: &Path, maximum: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(file)
        .context("Не удалось открыть файл")?
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= maximum,
        "Файл превышает допустимый размер"
    );
    Ok(bytes)
}

/// Файл создаётся в том же каталоге. no_clobber защищает отдельные находки.
pub fn atomic_write(file: &Path, bytes: &[u8], no_clobber: bool) -> Result<()> {
    let parent = file.parent().context("Не задан каталог файла")?;
    let mut temporary =
        tempfile::NamedTempFile::new_in(parent).context("Не удалось создать временный файл")?;
    temporary
        .write_all(bytes)
        .context("Ошибка записи; прогресс не подтверждён")?;
    temporary.as_file().sync_all()?;
    if no_clobber {
        temporary
            .persist_noclobber(file)
            .map_err(|_| anyhow!("Результат уже существует или недоступен для записи"))?;
    } else {
        temporary
            .persist(file)
            .map_err(|_| anyhow!("Не удалось атомарно сохранить файл"))?;
    }
    #[cfg(unix)]
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn load_legacy_key(directory: &Path) -> Result<Zeroizing<[u8; 32]>> {
    let file = directory.join("master-key.bin");
    let metadata = fs::symlink_metadata(&file)
        .context("Не найден master-key.bin старой сессии; восстановите резервную копию")?;
    ensure!(
        metadata.file_type().is_file() && metadata.len() == 32,
        "Некорректный локальный ключ; файл не изменён"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            metadata.permissions().mode() & 0o777 == 0o600,
            "Локальный ключ должен иметь права 0600"
        );
    }
    let mut key = Zeroizing::new([0; 32]);
    let mut input = File::open(file)?;
    input.read_exact(key.as_mut())?;
    let mut trailing = [0; 1];
    ensure!(
        input.read(&mut trailing)? == 0,
        "Некорректная длина локального ключа"
    );
    Ok(key)
}

fn load_encrypted<T: DeserializeOwned>(file: &Path, key: &[u8; 32]) -> Result<T> {
    let raw = read_bounded(file)?;
    let envelope: Envelope = toml::from_str(
        std::str::from_utf8(&raw).map_err(|_| anyhow!("Повреждённая оболочка"))?,
    )
    .map_err(|_| {
        anyhow!("Повреждённая оболочка или несовместимый старый формат; исходный файл не изменён")
    })?;
    ensure!(
        envelope.schema_version == 2,
        "Неподдерживаемая версия; исходный файл не изменён"
    );
    let nonce = STANDARD
        .decode(envelope.nonce)
        .map_err(|_| anyhow!("Повреждён nonce"))?;
    ensure!(
        nonce.len() == 24,
        "Некорректные длины параметров шифрования"
    );
    let ciphertext = STANDARD
        .decode(envelope.ciphertext)
        .map_err(|_| anyhow!("Повреждён ciphertext"))?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| anyhow!("Ошибка ключа"))?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: AAD,
                },
            )
            .map_err(|_| anyhow!("Неверный локальный ключ или повреждённые данные"))?,
    );
    toml::from_str(std::str::from_utf8(&plaintext).map_err(|_| anyhow!("Повреждённое содержимое"))?)
        .map_err(|_| anyhow!("Некорректное содержимое защищённого файла"))
}

pub fn file_exists(file: &Path) -> Result<bool> {
    match fs::metadata(file) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).context("Не удалось проверить наличие файла"),
    }
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct WalletRecord {
    #[serde(rename = "Версия_формата", alias = "schema_version")]
    pub schema_version: u32,
    #[serde(rename = "Сессия", alias = "session_id")]
    pub session_id: String,
    #[serde(rename = "Индекс", alias = "index")]
    pub index: u64,
    #[serde(rename = "Адрес", alias = "address")]
    pub address: String,
    #[serde(rename = "Сид_фраза", alias = "words")]
    pub words: String,
    #[serde(rename = "Мнемоника", alias = "mnemonic_type")]
    pub mnemonic_type: String,
    #[serde(rename = "Путь", alias = "derivation_path")]
    pub derivation_path: String,
    #[serde(rename = "Версия_кошелька", alias = "wallet_version")]
    pub wallet_version: String,
    #[serde(rename = "ID_кошелька", alias = "wallet_id")]
    pub wallet_id: String,
    #[serde(rename = "Сеть", alias = "network")]
    pub network: String,
    #[serde(rename = "Рабочая_цепочка", alias = "workchain")]
    pub workchain: u8,
    #[serde(rename = "Пароль_BIP39", alias = "bip39_passphrase")]
    pub bip39_passphrase: String,
}

pub fn load_session(directory: &Path) -> Result<Option<Session>> {
    let file = directory.join("session.toml");
    if !file_exists(&file)? {
        return Ok(None);
    }
    let bytes = Zeroizing::new(read_bounded(&file)?);
    let value = session_document(&bytes)?;
    let session: Session = if value.get("ciphertext").is_some() {
        ensure!(
            value
                .get("schema_version")
                .and_then(toml::Value::as_integer)
                == Some(2),
            "Сессия версии 1 несовместима; исходные файлы сохранены"
        );
        let key = load_legacy_key(directory)?;
        load_encrypted(&file, &key)?
    } else {
        toml::from_str(std::str::from_utf8(&bytes)?)
            .map_err(|_| anyhow!("Повреждённая сессия; исходный файл не изменён"))?
    };
    session.validate_target(&session.target_suffix)?;
    Ok(Some(session))
}

fn session_document(bytes: &[u8]) -> Result<toml::Value> {
    toml::from_str(std::str::from_utf8(bytes).map_err(|_| anyhow!("Повреждённая сессия"))?)
        .map_err(|_| anyhow!("Повреждённая сессия; исходный файл не изменён"))
}

pub fn save_session(directory: &Path, session: &Session) -> Result<()> {
    session.validate_target(&session.target_suffix)?;
    let file = directory.join("session.toml");
    if file_exists(&file)? {
        // Валидация выполняется до любой записи, включая резервную копию.
        load_session(directory)?;
        let previous = Zeroizing::new(read_bounded(&file)?);
        if session_document(&previous)?.get("ciphertext").is_some() {
            let backup = directory.join("session-v0.2.backup.toml");
            if file_exists(&backup)? {
                ensure!(
                    read_bounded(&backup)? == *previous,
                    "Резервная копия старой сессии отличается; файлы не изменены"
                );
            } else {
                atomic_write(&backup, &previous, true)?;
            }
        }
    }
    let text = Zeroizing::new(
        toml::to_string(session).map_err(|_| anyhow!("Ошибка сериализации сессии"))?,
    );
    atomic_write(&file, text.as_bytes(), false)
}

fn validate_wallet(record: &WalletRecord) -> Result<()> {
    ensure!(
        record.schema_version == 1
            && record.session_id.len() == 32
            && record
                .session_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            && record.mnemonic_type == "BIP39"
            && record.derivation_path == "m/44'/607'/0'"
            && record.wallet_version == "V5R1"
            && record.wallet_id == "0x7fffff11"
            && record.network == "mainnet"
            && record.workchain == 0
            && record.bip39_passphrase.is_empty(),
        "Неподдерживаемые параметры кошелька"
    );
    let mnemonic = bip39::Mnemonic::parse_in_normalized(bip39::Language::English, &record.words)
        .map_err(|_| anyhow!("Неверная мнемоника в результате"))?;
    let entropy = Zeroizing::new(mnemonic.to_entropy());
    let entropy: &[u8; 32] = entropy
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("Ожидаются 24 слова"))?;
    ensure!(
        record
            .words
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            == record.words,
        "Сид-фраза должна быть записана одной строкой"
    );
    ensure!(
        derive_wallet(entropy)?.address == record.address,
        "Адрес не соответствует словам"
    );
    Ok(())
}

pub fn load_wallets(directory: &Path) -> Result<Vec<WalletRecord>> {
    let file = directory.join("wallets.txt");
    if !file_exists(&file)? {
        return Ok(Vec::new());
    }
    let bytes = Zeroizing::new(read_with_limit(&file, MAX_WALLETS_FILE)?);
    let text = std::str::from_utf8(&bytes).map_err(|_| anyhow!("Повреждён wallets.txt"))?;
    let mut records = Vec::new();
    let mut identities = std::collections::HashSet::new();
    let mut remaining = text;
    while !remaining.trim().is_empty() {
        remaining = remaining.trim_start();
        let (header, rest) = remaining
            .split_once('\n')
            .context("Незавершённая запись кошелька")?;
        let identity = header
            .strip_prefix("[TON-W5 ")
            .and_then(|value| value.strip_suffix(']'))
            .context("Повреждён маркер кошелька")?;
        let (body, rest) = rest
            .split_once("\n[/TON-W5]\n")
            .context("Незавершённая запись кошелька")?;
        let record = parse_wallet_block(identity, body)?;
        ensure!(
            identity == format!("{}:{}", record.session_id, record.index),
            "Маркер кошелька не соответствует содержимому"
        );
        ensure!(
            identities.insert((record.session_id.clone(), record.index)),
            "Повторный идентификатор в wallets.txt"
        );
        validate_wallet(&record)?;
        records.push(record);
        remaining = rest;
    }
    Ok(records)
}

fn parse_wallet_block(identity: &str, body: &str) -> Result<WalletRecord> {
    let (session, index) = identity
        .split_once(':')
        .context("Повреждён идентификатор записи")?;
    let mut lines = body.lines();
    let address = lines
        .next()
        .and_then(|line| line.strip_prefix("Адрес: "))
        .context("Отсутствует адрес кошелька")?;
    ensure!(
        lines.next() == Some("Сид-фраза (BIP39, 24 слова):"),
        "Отсутствует заголовок сид-фразы"
    );
    let words = lines.next().context("Отсутствует сид-фраза")?;
    ensure!(
        lines.next() == Some("Сеть: TON mainnet · W5/V5R1 · workchain 0")
            && lines.next() == Some("Путь: m/44'/607'/0' · wallet_id 0x7fffff11")
            && lines.next().is_none(),
        "Неподдерживаемые параметры записи кошелька"
    );
    Ok(WalletRecord {
        schema_version: 1,
        session_id: session.into(),
        index: index.parse().context("Повреждён индекс записи")?,
        address: address.into(),
        words: words.into(),
        mnemonic_type: "BIP39".into(),
        derivation_path: "m/44'/607'/0'".into(),
        wallet_version: "V5R1".into(),
        wallet_id: "0x7fffff11".into(),
        network: "mainnet".into(),
        workchain: 0,
        bip39_passphrase: String::new(),
    })
}

pub fn append_wallet(directory: &Path, record: &WalletRecord) -> Result<bool> {
    Ok(append_wallets(directory, std::iter::once(record))? != 0)
}

fn append_wallets<'a>(
    directory: &Path,
    incoming: impl IntoIterator<Item = &'a WalletRecord>,
) -> Result<usize> {
    let records = load_wallets(directory)?;
    let mut all: Vec<&WalletRecord> = records.iter().collect();
    let mut identities: std::collections::HashMap<(&str, u64), usize> = all
        .iter()
        .enumerate()
        .map(|(position, record)| ((record.session_id.as_str(), record.index), position))
        .collect();
    let mut count = 0;
    for record in incoming {
        validate_wallet(record)?;
        let identity = (record.session_id.as_str(), record.index);
        if let Some(position) = identities.get(&identity) {
            let previous = all[*position];
            ensure!(
                previous.address == record.address && previous.words == record.words,
                "Существующая находка не соответствует повторённой пачке"
            );
        } else {
            identities.insert(identity, all.len());
            all.push(record);
            count += 1;
        }
    }
    if count == 0 {
        return Ok(0);
    }
    let mut text = Zeroizing::new(String::new());
    for record in all {
        use std::fmt::Write;
        writeln!(
            &mut *text,
            "[TON-W5 {}:{}]",
            record.session_id, record.index
        )?;
        writeln!(&mut *text, "Адрес: {}", record.address)?;
        writeln!(&mut *text, "Сид-фраза (BIP39, 24 слова):")?;
        writeln!(&mut *text, "{}", record.words)?;
        writeln!(&mut *text, "Сеть: TON mainnet · W5/V5R1 · workchain 0")?;
        writeln!(&mut *text, "Путь: m/44'/607'/0' · wallet_id 0x7fffff11")?;
        text.push_str("[/TON-W5]\n\n");
        ensure!(
            text.len() as u64 <= MAX_WALLETS_FILE,
            "Файл превышает допустимый размер"
        );
    }
    atomic_write(&directory.join("wallets.txt"), text.as_bytes(), false)?;
    Ok(count)
}

pub fn migrate_legacy_wallets(directory: &Path, session: &Session) -> Result<usize> {
    session.validate_target(&session.target_suffix)?;
    // После завершённого переноса открытый wallets.txt — источник результатов;
    // старый ключ больше не требуется для уже перенесённых записей.
    let imported: std::collections::HashSet<u64> = load_wallets(directory)?
        .iter()
        .filter(|record| record.session_id == session.id)
        .map(|record| record.index)
        .collect();
    let prefix = format!("wallet-{}-", session.id);
    let mut files = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if let Some(index) = name
            .strip_prefix(&prefix)
            .and_then(|name| name.strip_suffix(".toml"))
        {
            let index = index
                .parse::<u64>()
                .context("Некорректный индекс старого кошелька")?;
            if imported.contains(&index) {
                continue;
            }
            ensure!(
                entry.file_type()?.is_file(),
                "Старый кошелёк должен быть обычным файлом"
            );
            files.push((index, entry.path()));
        }
    }
    if files.is_empty() {
        return Ok(0);
    }
    files.sort_unstable_by_key(|(index, _)| *index);
    let key = load_legacy_key(directory)?;
    let mut validated = Vec::with_capacity(files.len());
    for (index, file) in files {
        let record: WalletRecord = load_encrypted(&file, &key)?;
        ensure!(
            record.session_id == session.id && record.index == index,
            "Старый кошелёк не соответствует имени файла"
        );
        validate_wallet(&record)?;
        validated.push(record);
    }
    append_wallets(directory, &validated)
}
