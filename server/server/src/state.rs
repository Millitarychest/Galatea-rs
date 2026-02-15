use std::path::PathBuf;
use std::sync::OnceLock;

use crate::{db::{self, DbPool}, utils};

static APP_CONTEXT: OnceLock<AppContext> = OnceLock::new();
static STARTUP_CONFIG: OnceLock<StartupConfig> = OnceLock::new();

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

    pub fn global() -> Option<&'static AppContext> {
        APP_CONTEXT.get()
    }

    pub fn ensure_global() -> Result<&'static AppContext, String> {
        if let Some(context) = Self::global() {
            return Ok(context);
        }

        let startup = STARTUP_CONFIG
            .get()
            .ok_or_else(|| "Startup config has not been initialized".to_string())?;
        mimic_core::mimic_log!(
            "AppContext missing; attempting lazy init using startup config on port {}",
            startup.port
        );
        let db_path = startup
            .db_path
            .to_str()
            .ok_or_else(|| format!("Startup DB path is not valid UTF-8: {:?}", startup.db_path))?;
        let db_pool = db::init_db_pool(db_path).map_err(|e| format!("Failed to initialize DB pool: {e}"))?;
        let context = AppContext::new(db_pool);

        let _ = APP_CONTEXT.set(context);
        APP_CONTEXT
            .get()
            .ok_or_else(|| "Failed to initialize global context".to_string())
    }

    pub fn set_global(self) -> Result<(), String> {
        APP_CONTEXT
            .set(self)
            .map_err(|_| "Global AppContext is already initialized".to_string())
    }
}

#[derive(Clone)]
pub struct StartupConfig {
    pub db_path: PathBuf,
    pub port: u16,
}

pub fn set_startup_config(db_path: PathBuf, port: u16) -> Result<(), String> {
    STARTUP_CONFIG
        .set(StartupConfig { db_path, port })
        .map_err(|_| "Startup config is already initialized".to_string())
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
