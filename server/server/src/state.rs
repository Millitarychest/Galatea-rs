use std::sync::OnceLock;

use crate::{db::{self, DbPool}, utils};

static APP_CONTEXT: OnceLock<AppContext> = OnceLock::new();

pub struct AppContext {
    pub db_pool: DbPool,
    pub config: AppConfig
}

impl AppContext {
    pub fn new(db_pool: DbPool) -> Self {
        let config = AppConfig::load_or_init(&db_pool);
        Self { 
            db_pool,
            config
        }
    }

    pub fn global() -> &'static AppContext {
        APP_CONTEXT.get().expect("AppContext not initialized")
    }

    pub fn set_global(self) -> Result<(), ()> {
        APP_CONTEXT.set(self).map_err(|_| ())
    }
}


pub struct AppConfig {
    pub agent_registration_secret: String
}

impl AppConfig {
    pub fn new() -> Self{
        Self { agent_registration_secret: utils::generate_passphrase(5) }
    }
    pub fn load_or_init(pool: &db::DbPool) -> Self{
        if let Some(config) = db::fetch_persisted_config(pool) {
            return config;
        }
        let config = AppConfig::new();
        if let Err(e) = db::persist_config(pool, &config) {
            mimic_core::mimic_log!("Failed to persist generated server config: {}", e);
        }
        config
    }
}
