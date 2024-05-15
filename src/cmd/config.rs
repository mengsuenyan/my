use std::sync::OnceLock;

use config::Config;
use serde::{Deserialize, Serialize};

use super::git::config::GitConfig;

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct MyConfig {
    // byte size
    pub io_buf_size: usize,

    // temporary buffer byte size,
    pub tmp_buf_size: usize,

    // maximum creatable threads
    pub threads: usize,

    pub git: GitConfig,
}

impl Default for MyConfig {
    fn default() -> Self {
        Self {
            io_buf_size: 8 * 1024,
            tmp_buf_size: 1024,
            threads: (num_cpus::get() >> 1).max(1),
            git: GitConfig::default(),
        }
    }
}

impl MyConfig {
    pub fn config() -> &'static Self {
        Self::config_with_file(None)
    }

    pub fn config_with_file(f: Option<&str>) -> &'static Self {
        static CONFIG: OnceLock<MyConfig> = OnceLock::new();

        CONFIG.get_or_init(|| {
            let default_config = Config::try_from(&MyConfig::default()).unwrap();

            let mut config = Config::builder().add_source(default_config).add_source(
                config::Environment::with_prefix("MY")
                    .try_parsing(true)
                    .separator("__"),
            );

            if let Some(f) = f {
                config = config.add_source(config::File::with_name(f).required(false));
            }

            let config = config.build().unwrap();
            let mut myconfig: MyConfig = config.try_deserialize().unwrap();

            myconfig.threads = myconfig.threads.max(1);

            log::trace!("{:?}", myconfig);

            myconfig
        })
    }

    pub fn tmp_buf() -> Vec<u8> {
        Vec::with_capacity(Self::config().tmp_buf_size.clamp(0, 8 * 1024))
    }
}
