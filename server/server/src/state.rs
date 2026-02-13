use std::sync::OnceLock;

use crate::db::DbPool;

static APP_CONTEXT: OnceLock<AppContext> = OnceLock::new();

pub struct AppContext {
    pub db_pool: DbPool,
}

impl AppContext {
    pub fn new(db_pool: DbPool) -> Self {
        Self { db_pool }
    }

    pub fn global() -> &'static AppContext {
        APP_CONTEXT.get().expect("AppContext not initialized")
    }

    pub fn set_global(self) -> Result<(), ()> {
        APP_CONTEXT.set(self).map_err(|_| ())
    }
}
