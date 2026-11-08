//! OpenCL W5: две постоянные группы буферов и явное владение пачками.
use std::ptr;
use std::time::Instant;

use anyhow::{Context as _, Result, anyhow, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bip39::{Language, Mnemonic};
use opencl3::command_queue::{CL_QUEUE_PROFILING_ENABLE, CommandQueue};
use opencl3::context::Context;
use opencl3::device::{CL_DEVICE_TYPE_GPU, Device, get_all_devices};
use opencl3::event::Event;
use opencl3::kernel::Kernel;
use opencl3::memory::{Buffer, CL_MEM_READ_WRITE, ClMem};
use opencl3::program::Program;
use opencl3::types::{CL_BLOCKING, cl_event};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::{crypto::derive_wallet, pattern::SuffixPattern};

const DEPTH: usize = 2;
const HIT_CAPACITY: usize = 16;
const MAX_BATCH_SIZE: usize = 1_048_576;
const ED_SOURCE: &str = include_str!("../kernels/bip39-ed25519.cl");
const KDF_SOURCE: &str = include_str!("../kernels/ton-pbkdf2.cl");

/// Ограничения проверяются до загрузки OpenCL и выделения памяти.
pub fn validate_batch_size(size: usize) -> Result<()> {
    ensure!(
        (128..=MAX_BATCH_SIZE).contains(&size) && size.is_multiple_of(128),
        "Размер GPU-пачки должен быть кратен 128 и находиться между 128 и {MAX_BATCH_SIZE}"
    );
    Ok(())
}

/// Kernel возвращает id*4+version; интерфейс приложения использует только id W5.
pub fn decode_hits(count: u32, hits: &[u32], batch: usize) -> Result<Vec<usize>> {
    let count = count as usize;
    ensure!(
        count <= HIT_CAPACITY && count <= hits.len(),
        "Переполнение GPU hit-буфера; пачка не подтверждена"
    );
    let mut result = Vec::with_capacity(count);
    for &hit in &hits[..count] {
        ensure!(
            hit % 4 == 3,
            "GPU вернул совпадение другого контракта вместо W5"
        );
        let index = (hit / 4) as usize;
        ensure!(index < batch, "GPU вернул индекс за пределами пачки");
        result.push(index);
    }
    result.sort_unstable();
    ensure!(
        !result.windows(2).any(|pair| pair[0] == pair[1]),
        "GPU вернул повторяющееся совпадение"
    );
    Ok(result)
}

/// Ticket одноразовый, связан с экземпляром движка и поколением слота.
#[derive(Debug)]
pub struct BatchTicket {
    engine: u64,
    slot: usize,
    generation: u64,
}

#[derive(Default)]
struct Ownership {
    slots: [Option<u64>; DEPTH],
    next: u64,
}

impl Ownership {
    fn reserve(&mut self) -> Result<(usize, u64)> {
        let slot = self
            .slots
            .iter()
            .position(Option::is_none)
            .context("Обе GPU-пачки заняты: сначала вызовите collect")?;
        self.next = self
            .next
            .checked_add(1)
            .context("Исчерпан счётчик GPU tickets")?;
        self.slots[slot] = Some(self.next);
        Ok((slot, self.next))
    }
    fn validate(&self, slot: usize, generation: u64) -> Result<()> {
        ensure!(
            self.slots.get(slot) == Some(&Some(generation)),
            "Недействительный или уже обработанный GPU ticket"
        );
        Ok(())
    }
    fn release(&mut self, slot: usize, generation: u64) -> Result<()> {
        self.validate(slot, generation)?;
        self.slots[slot] = None;
        Ok(())
    }
}

#[derive(Debug, Default, Clone)]
pub struct GpuProfile {
    pub h2d_ns: u64,
    pub bip39_ns: u64,
    pub kdf_ns: u64,
    pub slip10_ns: u64,
    pub ed25519_ns: u64,
    pub filter_ns: u64,
    pub d2h_ns: u64,
    pub collect_wall_ns: u64,
    pub maximum_dispatch_ns: u64,
}

#[derive(Clone, Copy)]
enum Stage {
    Upload,
    Password,
    Kdf,
    Slip10,
    Ed25519,
    Filter,
}
struct Pending {
    count: usize,
    suffix: String,
    events: Vec<(Stage, Event)>,
}
struct Slot {
    entropy: Buffer<u8>,
    passwords: Buffer<u64>,
    states: Buffer<u64>,
    seeds: Buffer<u64>,
    private: Buffer<u8>,
    public: Buffer<u8>,
    count: Buffer<u32>,
    hits: Buffer<u32>,
    samples: Buffer<u32>,
    host_entropy: Zeroizing<Vec<u8>>,
    pending: Option<Pending>,
}

fn buffer<T>(context: &Context, count: usize) -> Result<Buffer<T>> {
    // Размеры вычислены из ограниченной capacity; host_ptr отсутствует.
    unsafe { Buffer::create(context, CL_MEM_READ_WRITE, count, ptr::null_mut()) }
        .context("Не удалось выделить OpenCL-буфер")
}
impl Slot {
    fn new(context: &Context, capacity: usize) -> Result<Self> {
        Ok(Self {
            entropy: buffer(context, capacity * 32)?,
            passwords: buffer(context, capacity * 16)?,
            states: buffer(context, capacity * 32)?,
            seeds: buffer(context, capacity * 8)?,
            private: buffer(context, capacity * 32)?,
            public: buffer(context, capacity * 32)?,
            count: buffer(context, 1)?,
            hits: buffer(context, HIT_CAPACITY)?,
            samples: buffer(context, 96)?,
            host_entropy: Zeroizing::new(vec![0; capacity * 32]),
            pending: None,
        })
    }
}

static NEXT_ENGINE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

pub struct GpuEngine {
    queue: CommandQueue,
    upload_queue: CommandQueue,
    read_queue: CommandQueue,
    slots: [Slot; DEPTH],
    ownership: Ownership,
    id: u64,
    capacity: usize,
    device_name: String,
    poisoned: bool,
    words: Buffer<u8>,
    salt: Buffer<u8>,
    passwords: Kernel,
    init: Kernel,
    loops: Kernel,
    result: Kernel,
    hd: Kernel,
    ed: Kernel,
    matcher: Kernel,
    last_profile: GpuProfile,
}

pub fn devices() -> Result<Vec<String>> {
    get_all_devices(CL_DEVICE_TYPE_GPU)
        .context("Не удалось загрузить OpenCL или получить GPU; установите драйвер с OpenCL")?
        .into_iter()
        .map(|id| {
            let device = Device::new(id);
            Ok(format!("{} — {}", device.vendor()?, device.name()?))
        })
        .collect()
}

// В отличие от ExecuteKernel, set_arg возвращает ошибку, а не panic драйвера.
macro_rules! launch {
    ($kernel:expr, $queue:expr, $size:expr, $wait:expr; $($arg:expr),+ $(,)?) => {{
        let kernel = &$kernel;
        let mut index = 0;
        unsafe {
            $(kernel.set_arg(index, &$arg)?; index += 1;)+
            let _ = index;
            $queue.enqueue_nd_range_kernel(kernel.get(), 1, ptr::null(),
                [$size].as_ptr(), ptr::null(), $wait)?
        }
    }};
}

impl GpuEngine {
    pub fn new(device_index: usize, batch_size: usize) -> Result<Self> {
        validate_batch_size(batch_size)?;
        let ids = get_all_devices(CL_DEVICE_TYPE_GPU)
            .context("OpenCL недоступен: нужен драйвер GPU с поддержкой OpenCL")?;
        let device = Device::new(
            *ids.get(device_index)
                .context("Выбранный GPU отсутствует; выполните devices")?,
        );
        let device_name = format!("{} — {}", device.vendor()?, device.name()?);
        // ulong/device endian должны совпадать при передаче числовых seeds/samples.
        ensure!(
            device.endian_little()? == cfg!(target_endian = "little"),
            "Порядок байтов OpenCL-устройства не поддерживается"
        );
        let context = Context::from_device(&device).context("Создание OpenCL context")?;
        let queue = CommandQueue::create_default(&context, CL_QUEUE_PROFILING_ENABLE)?;
        let upload_queue = CommandQueue::create_default(&context, CL_QUEUE_PROFILING_ENABLE)?;
        let read_queue = CommandQueue::create_default(&context, CL_QUEUE_PROFILING_ENABLE)?;
        let build = |source| {
            Program::create_and_build_from_source(&context, source, "-cl-std=CL1.2")
                .map_err(|log| anyhow!("Ошибка компиляции OpenCL kernels: {log}"))
        };
        let ed_program = build(ED_SOURCE)?;
        let kdf_program = build(KDF_SOURCE)?;
        let mut words = buffer(&context, 2048 * 9)?;
        let mut word_data = vec![0u8; 2048 * 9];
        for (index, word) in Language::English.word_list().iter().enumerate() {
            ensure!(word.len() <= 8, "Неподдерживаемая длина слова BIP39");
            word_data[index * 9..index * 9 + word.len()].copy_from_slice(word.as_bytes());
        }
        let mut salt = buffer(&context, 8)?;
        unsafe {
            upload_queue.enqueue_write_buffer(&mut words, CL_BLOCKING, 0, &word_data, &[])?;
            upload_queue.enqueue_write_buffer(&mut salt, CL_BLOCKING, 0, b"mnemonic", &[])?;
        }
        let id = NEXT_ENGINE
            .fetch_update(
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
                |id| id.checked_add(1),
            )
            .map_err(|_| anyhow!("Исчерпан счётчик экземпляров GPU"))?;
        Ok(Self {
            queue,
            upload_queue,
            read_queue,
            slots: [
                Slot::new(&context, batch_size)?,
                Slot::new(&context, batch_size)?,
            ],
            ownership: Ownership::default(),
            id,
            capacity: batch_size,
            device_name,
            poisoned: false,
            words,
            salt,
            passwords: Kernel::create(&ed_program, "bip39_passwords")?,
            init: Kernel::create(&kdf_program, "init_pbkdf")?,
            loops: Kernel::create(&kdf_program, "loop_pbkdf")?,
            result: Kernel::create(&kdf_program, "result_pbkdf")?,
            hd: Kernel::create(&kdf_program, "slip10_ton")?,
            ed: Kernel::create(&ed_program, "ed25519_generate")?,
            matcher: Kernel::create(&ed_program, "w5_match")?,
            last_profile: GpuProfile::default(),
        })
    }

    /// До двух незавершённых tickets. Вход копируется в постоянный host-буфер слота.
    pub fn submit(&mut self, entropy: &[[u8; 32]], pattern: &SuffixPattern) -> Result<BatchTicket> {
        ensure!(
            !self.poisoned,
            "GPU-движок остановлен после ошибки; создайте новый экземпляр"
        );
        validate_batch_size(entropy.len())?;
        ensure!(
            entropy.len() <= self.capacity,
            "Пачка превышает выделенную GPU capacity"
        );
        let (slot, generation) = self.ownership.reserve()?;
        let outcome = self.enqueue(slot, entropy, pattern);
        if let Err(error) = outcome {
            // Частично поставленные команды не должны дать переиспользовать слот.
            self.poisoned = true;
            return Err(
                error.context("Не удалось отправить GPU-пачку; её checkpoint не подтверждён")
            );
        }
        Ok(BatchTicket {
            engine: self.id,
            slot,
            generation,
        })
    }

    fn enqueue(
        &mut self,
        index: usize,
        entropy: &[[u8; 32]],
        pattern: &SuffixPattern,
    ) -> Result<()> {
        let slot = &mut self.slots[index];
        let n = entropy.len() as u32;
        let entropy_bytes = entropy.as_flattened();
        slot.host_entropy[..entropy_bytes.len()].copy_from_slice(entropy_bytes);
        // Блокирующая малая H2D-копия исключает dangling host pointers даже при
        // ошибке драйвера. Вычисления двух пачек остаются в очереди одновременно.
        let upload = unsafe {
            self.upload_queue.enqueue_write_buffer(
                &mut slot.entropy,
                CL_BLOCKING,
                0,
                &slot.host_entropy[..entropy.len() * 32],
                &[],
            )?
        };
        let reset = unsafe {
            self.upload_queue
                .enqueue_fill_buffer(&mut slot.count, &[0u32], 0, 4, &[])?
        };
        self.upload_queue.flush()?;
        let mut events = vec![(Stage::Upload, upload)];
        let size = entropy.len();
        let previous = |events: &[(Stage, Event)]| -> Result<[cl_event; 1]> {
            Ok([events.last().context("Отсутствует GPU event")?.1.get()])
        };
        let event = launch!(self.passwords, self.queue, size, &previous(&events)?;
            slot.entropy.get(), self.words.get(), slot.passwords.get(), n);
        events.push((Stage::Password, event));
        let event = launch!(self.init, self.queue, size, &previous(&events)?;
            slot.passwords.get(), self.salt.get(), 8u32, slot.states.get(), n, 16u32);
        events.push((Stage::Kdf, event));
        let mut remaining = 2047u32;
        while remaining != 0 {
            let iterations = remaining.min(256);
            let event = launch!(self.loops, self.queue, size, &previous(&events)?;
                slot.states.get(), n, iterations);
            events.push((Stage::Kdf, event));
            remaining -= iterations;
        }
        let event = launch!(self.result, self.queue, size, &previous(&events)?;
            slot.states.get(), n, slot.seeds.get());
        events.push((Stage::Kdf, event));
        let event = launch!(self.hd, self.queue, size, &previous(&events)?;
            slot.seeds.get(), slot.private.get(), n);
        events.push((Stage::Slip10, event));
        let event = launch!(self.ed, self.queue, size, &previous(&events)?;
            slot.private.get(), slot.public.get(), 1u32);
        events.push((Stage::Ed25519, event));
        let waits = [previous(&events)?[0], reset.get()];
        let event = launch!(self.matcher, self.queue, size, &waits;
            slot.public.get(), n, slot.count.get(), slot.hits.get(), slot.samples.get(),
            0u32, 0u32, pattern.value(), pattern.mask(), 8u32);
        events.push((Stage::Filter, event));
        // Сохраняем события до flush: при ошибке слот остаётся занятым.
        slot.pending = Some(Pending {
            count: size,
            suffix: pattern.suffix().to_owned(),
            events,
        });
        self.queue.flush().context("Отправка OpenCL commands")?;
        Ok(())
    }

    fn pending(&self, ticket: &BatchTicket) -> Result<&Pending> {
        ensure!(
            ticket.engine == self.id,
            "GPU ticket принадлежит другому движку"
        );
        self.ownership.validate(ticket.slot, ticket.generation)?;
        self.slots[ticket.slot]
            .pending
            .as_ref()
            .context("Нет данных GPU-пачки")
    }

    /// CPU-проверка каждого hit выполняется до освобождения слота.
    pub fn collect(&mut self, ticket: BatchTicket) -> Result<Vec<usize>> {
        self.pending(&ticket)?;
        let result = self.collect_inner(&ticket);
        match result {
            Ok(hits) => {
                self.slots[ticket.slot].pending = None;
                self.slots[ticket.slot]
                    .host_entropy
                    .as_mut_slice()
                    .zeroize();
                self.ownership.release(ticket.slot, ticket.generation)?;
                Ok(hits)
            }
            Err(error) => {
                self.poisoned = true;
                Err(error.context("GPU-пачка не прошла проверку; checkpoint не подтверждён"))
            }
        }
    }

    fn collect_inner(&mut self, ticket: &BatchTicket) -> Result<Vec<usize>> {
        let started = Instant::now();
        let slot = &self.slots[ticket.slot];
        let pending = self.pending(ticket)?;
        let complete = pending
            .events
            .last()
            .context("Отсутствует завершающий GPU event")?
            .1
            .get();
        let mut count = [0u32];
        let mut raw_hits = [0u32; HIT_CAPACITY];
        let mut first_seed = Zeroizing::new([0u64; 8]);
        let read_count = unsafe {
            self.read_queue.enqueue_read_buffer(
                &slot.count,
                CL_BLOCKING,
                0,
                &mut count,
                &[complete],
            )?
        };
        ensure!(
            count[0] as usize <= HIT_CAPACITY,
            "Переполнение GPU hit-буфера; пачка не подтверждена"
        );
        let read_hits = if count[0] == 0 {
            None
        } else {
            Some(unsafe {
                self.read_queue.enqueue_read_buffer(
                    &slot.hits,
                    CL_BLOCKING,
                    0,
                    &mut raw_hits[..count[0] as usize],
                    &[complete],
                )?
            })
        };
        let read_seed = unsafe {
            self.read_queue.enqueue_read_buffer(
                &slot.seeds,
                CL_BLOCKING,
                0,
                &mut first_seed[..],
                &[complete],
            )?
        };
        let mnemonic = Mnemonic::from_entropy(&slot.host_entropy[..32])?;
        let expected = Zeroizing::new(mnemonic.to_seed(""));
        let mut seed_bytes = Zeroizing::new([0u8; 64]);
        for (dst, word) in seed_bytes.chunks_exact_mut(8).zip(first_seed.iter()) {
            dst.copy_from_slice(&word.to_be_bytes());
        }
        ensure!(
            seed_bytes[..] == expected[..],
            "GPU PBKDF2 отличается от CPU BIP39"
        );
        let hits = decode_hits(count[0], &raw_hits, pending.count)?;
        for &index in &hits {
            let entropy: &[u8; 32] = slot.host_entropy[index * 32..(index + 1) * 32].try_into()?;
            let wallet = derive_wallet(entropy)?;
            ensure!(
                wallet.address.ends_with(&pending.suffix),
                "GPU hit не подтверждён независимым CPU W5"
            );
        }
        let mut profile = GpuProfile::default();
        for (stage, event) in &pending.events {
            let ns = event_duration(event)?;
            match stage {
                Stage::Upload => profile.h2d_ns += ns,
                Stage::Password => profile.bip39_ns += ns,
                Stage::Kdf => profile.kdf_ns += ns,
                Stage::Slip10 => profile.slip10_ns += ns,
                Stage::Ed25519 => profile.ed25519_ns += ns,
                Stage::Filter => profile.filter_ns += ns,
            }
            if !matches!(stage, Stage::Upload) {
                profile.maximum_dispatch_ns = profile.maximum_dispatch_ns.max(ns);
            }
        }
        profile.d2h_ns = event_duration(&read_count)?
            + read_hits
                .as_ref()
                .map(event_duration)
                .transpose()?
                .unwrap_or(0)
            + event_duration(&read_seed)?;
        profile.collect_wall_ns = started.elapsed().as_nanos().try_into().unwrap_or(u64::MAX);
        self.last_profile = profile;
        Ok(hits)
    }

    pub fn scan(&mut self, entropy: &[[u8; 32]], pattern: &SuffixPattern) -> Result<Vec<usize>> {
        let ticket = self.submit(entropy, pattern)?;
        self.collect(ticket)
    }

    pub fn device_name(&self) -> &str {
        &self.device_name
    }

    pub fn last_profile(&self) -> &GpuProfile {
        &self.last_profile
    }

    /// Только явная команда check: эта функция запускает GPU.
    pub fn self_test(&mut self) -> Result<()> {
        ensure!(
            self.ownership.slots.iter().all(Option::is_none),
            "Self-test требует свободных GPU slots"
        );
        let mut entropy = vec![[0u8; 32]; 128];
        entropy[1] = [255; 32];
        for (index, value) in entropy.iter_mut().enumerate().skip(2) {
            *value = Sha256::digest((index as u64).to_be_bytes()).into();
        }
        // Найдены по публичному SHA256(counter.to_be_bytes()), без секретов.
        for (slot, counter) in [(2, 5366u64), (3, 61922), (4, 42162)] {
            entropy[slot] = Sha256::digest(counter.to_be_bytes()).into();
        }
        for (slot, length) in [(2, 127), (3, 128), (4, 129)] {
            ensure!(
                Mnemonic::from_entropy(&entropy[slot])?.to_string().len() == length,
                "Изменилась публичная BIP39 фикстура границы HMAC"
            );
        }
        ensure!(entropy.iter().any(|value| Mnemonic::from_entropy(value).is_ok_and(|m| m.to_string().len() > 128)),
            "Публичная self-test фикстура не покрывает длинный HMAC пароль");
        let addresses = entropy
            .iter()
            .map(|value| Ok(derive_wallet(value)?.address))
            .collect::<Result<Vec<_>>>()?;
        // Проверяем все seeds, включая 0/ff и длинные мнемоники, и StateInit samples.
        let ticket = self.submit(&entropy, &SuffixPattern::new(&addresses[0][44..])?)?;
        let pending = self.pending(&ticket)?;
        let complete = pending.events.last().context("Нет GPU event")?.1.get();
        let slot = &self.slots[ticket.slot];
        let mut seeds = Zeroizing::new(vec![0u64; entropy.len() * 8]);
        let mut samples = [0u32; 96];
        unsafe {
            self.read_queue.enqueue_read_buffer(
                &slot.seeds,
                CL_BLOCKING,
                0,
                &mut seeds[..],
                &[complete],
            )?;
            self.read_queue.enqueue_read_buffer(
                &slot.samples,
                CL_BLOCKING,
                0,
                &mut samples,
                &[complete],
            )?;
        }
        for (index, value) in entropy.iter().enumerate() {
            let expected = Zeroizing::new(Mnemonic::from_entropy(value)?.to_seed(""));
            let mut actual = Zeroizing::new([0u8; 64]);
            for (dst, word) in actual
                .chunks_exact_mut(8)
                .zip(&seeds[index * 8..index * 8 + 8])
            {
                dst.copy_from_slice(&word.to_be_bytes());
            }
            ensure!(
                actual[..] == expected[..],
                "Self-test: CPU/GPU BIP39 не совпадают для публичной фикстуры {index}"
            );
        }
        for (index, address) in addresses.iter().enumerate().take(3) {
            ensure!(
                sample_address(&samples[(index * 4 + 3) * 8..(index * 4 + 4) * 8]) == *address,
                "Self-test: CPU/GPU W5 StateInit не совпадают"
            );
        }
        let _ = self.collect(ticket)?;
        for sample_index in 0..4 {
            let target_address = sample_address(&samples[sample_index * 8..sample_index * 8 + 8]);
            for length in [4, 9, 10] {
                let pattern = SuffixPattern::new(&target_address[48 - length..])?;
                let hits = self.scan(&entropy, &pattern)?;
                let expected: Vec<usize> = addresses
                    .iter()
                    .enumerate()
                    .filter_map(|(index, address)| {
                        address.ends_with(pattern.suffix()).then_some(index)
                    })
                    .collect();
                ensure!(
                    hits == expected,
                    "Self-test: W5-only GPU suffix {length} не совпадает с CPU"
                );
                if sample_index == 3 {
                    ensure!(
                        hits.contains(&0),
                        "Self-test: положительный W5 hit отсутствует"
                    );
                }
            }
        }
        // Положительные находки завершают весь GPU-путь для границ HMAC.
        for index in 2..5 {
            for length in [4, 9, 10] {
                let pattern = SuffixPattern::new(&addresses[index][48 - length..])?;
                let hits = self.scan(&entropy, &pattern)?;
                let expected: Vec<usize> = addresses
                    .iter()
                    .enumerate()
                    .filter_map(|(i, address)| address.ends_with(pattern.suffix()).then_some(i))
                    .collect();
                ensure!(
                    hits == expected && hits.contains(&index),
                    "Self-test: GPU-путь длинной мнемоники не совпадает с CPU"
                );
            }
        }
        let pattern = SuffixPattern::new(&addresses[3][38..])?;
        let first = self.submit(&entropy, &pattern)?;
        let mut reversed = entropy.clone();
        reversed.reverse();
        let second = self.submit(&reversed, &pattern)?;
        ensure!(
            self.submit(&entropy, &pattern).is_err(),
            "Self-test: очередь GPU не ограничена двумя пачками"
        );
        reversed.fill([0; 32]);
        let expected: Vec<usize> = addresses
            .iter()
            .enumerate()
            .filter_map(|(i, address)| address.ends_with(pattern.suffix()).then_some(i))
            .collect();
        ensure!(
            self.collect(first)? == expected,
            "Self-test: потеряно владение первой GPU-пачкой"
        );
        let mut expected_reversed: Vec<usize> =
            expected.iter().map(|i| entropy.len() - 1 - i).collect();
        expected_reversed.sort_unstable();
        ensure!(
            self.collect(second)? == expected_reversed,
            "Self-test: потеряно владение второй GPU-пачкой"
        );
        ensure!(
            self.scan(&entropy, &pattern)? == expected,
            "Self-test: повторное использование GPU-слота некорректно"
        );
        Ok(())
    }
}

fn event_duration(event: &Event) -> Result<u64> {
    event
        .profiling_command_end()?
        .checked_sub(event.profiling_command_start()?)
        .context("Некорректные OpenCL profiling timestamps")
}

fn sample_address(words: &[u32]) -> String {
    let mut payload = vec![0x51u8, 0];
    for word in words {
        payload.extend_from_slice(&word.to_be_bytes());
    }
    let mut crc = 0u16;
    for &byte in &payload {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    payload.extend_from_slice(&crc.to_be_bytes());
    URL_SAFE_NO_PAD.encode(payload)
}

impl Drop for GpuEngine {
    fn drop(&mut self) {
        // Host pointers передаются только блокирующим копиям. Завершение очередей
        // сохраняет штатное время жизни device-буферов при раннем выходе.
        for queue in [&self.upload_queue, &self.queue, &self.read_queue] {
            if let Err(error) = queue.finish() {
                tracing::error!(%error, "Ошибка завершения OpenCL очереди");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Ownership;
    #[test]
    fn two_slots_cannot_be_reused_until_collected() {
        let mut state = Ownership::default();
        let first = state.reserve().unwrap();
        let second = state.reserve().unwrap();
        assert_ne!(first.0, second.0);
        assert!(state.reserve().is_err());
        state.release(first.0, first.1).unwrap();
        let third = state.reserve().unwrap();
        assert_eq!(third.0, first.0);
        assert_ne!(third.1, first.1);
        assert!(state.release(first.0, first.1).is_err());
        state.validate(second.0, second.1).unwrap();
    }
}
