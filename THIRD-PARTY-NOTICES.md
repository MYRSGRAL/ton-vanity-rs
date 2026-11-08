# Лицензии OpenCL-компонентов

Исходники `kernels/` перенесены из локального эталона TON-Vanity-W5-Windows
без изменений криптографических операций. Они встроены в бинарник через `include_str!`.
Rust-приложение распространяется под GNU AGPL v3; полный текст — `LICENSE-AGPL.txt`.

- Ed25519 OpenCL и таблицы предвычислений в `bip39-ed25519.cl`:
  [10gic/vanitygen-plusplus](https://github.com/10gic/vanitygen-plusplus),
  commit `302f493dd106ff2d41fed2d9b65bc2ae28868414`, GNU AGPL v3.
  Исходный Ed25519 ref10 отмечен upstream как public domain. Исходные заголовки сохранены.
- SHA256 в `bip39-ed25519.cl`:
  [ton-org/vanity](https://github.com/ton-org/vanity), MIT,
  Copyright 2025 TON Studio. Текст — `LICENSE-TON-VANITY.txt`.
- SHA512 в `ton-pbkdf2.cl`:
  [alice/ton-vanity-cuda](https://git.nova.tokyo/alice/ton-vanity-cuda),
  commit `d2fdc46fe2f1f7718fa0efea57078170c5170083`.
  Атрибуция адаптации сохранена в исходнике; приложение и адаптации — AGPL v3,
  согласно уведомлению локального эталона.
- Английский список BIP39 формируется из зависимости `bip39`, не требует отдельного
  файла данных. [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
  и реализация `bip39` распространяются под MIT/CC0 согласно их upstream notices.

Остальные Rust-зависимости сохраняют собственные лицензии, указанные в их
Cargo metadata и исходниках; их версии зафиксированы в `Cargo.lock`.
