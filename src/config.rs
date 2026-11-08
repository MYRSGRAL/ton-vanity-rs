use crate::{pattern::SuffixPattern, storage};
use anyhow::{Result, anyhow, ensure};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub schema_version: u32,
    pub target_suffix: String,
    pub device_index: usize,
    pub batch_size: usize,
    pub pipeline_depth: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            schema_version: 1,
            target_suffix: "myrsgraal".into(),
            device_index: 0,
            batch_size: 65536,
            pipeline_depth: 2,
        }
    }
}

impl Config {
    pub fn load(file: &Path) -> Result<Self> {
        let raw = storage::read_bounded(file)?;
        let mut settings: toml::Table = toml::from_str(
            std::str::from_utf8(&raw).map_err(|_| anyhow!("Настройки должны быть UTF-8"))?,
        )
        .map_err(|_| anyhow!("Некорректный TOML настроек"))?;
        // Старый конфиг должен позволять продолжить TON-сессию без ручной миграции.
        let had_watch = settings.remove("watch").is_some();
        let config: Self = toml::Value::Table(settings)
            .try_into()
            .map_err(|_| anyhow!("Некорректный TOML или неизвестное поле настроек"))?;
        config.validate()?;
        if had_watch {
            tracing::warn!("Секция [watch] больше не используется и будет проигнорирована");
        }
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1,
            "Неподдерживаемая версия конфигурации"
        );
        SuffixPattern::new(&self.target_suffix)?;
        ensure!(
            (128..=131072).contains(&self.batch_size) && self.batch_size.is_multiple_of(128),
            "batch_size: 128–131072, кратно 128"
        );
        ensure!(
            self.pipeline_depth == 2,
            "Поддерживается pipeline_depth = 2"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_unknown_and_invalid_config() {
        assert!(toml::from_str::<Config>("unknown = true").is_err());
        let mut config = Config::default();
        assert!(config.validate().is_ok());
        config.batch_size = 127;
        assert!(config.validate().is_err());
        config.batch_size = 128;
        config.target_suffix.clear();
        assert!(config.validate().is_err());
    }
}
