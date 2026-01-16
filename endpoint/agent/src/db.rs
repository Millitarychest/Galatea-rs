use std::path::Path;

use mimic_core::{error, mimic_log};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;



pub type DbPool = Pool<SqliteConnectionManager>;

pub fn init_db_pool(db_path: &str) -> error::Result<DbPool>{
    mimic_log!("Initializing Database at: {}", db_path);

    let manager = SqliteConnectionManager::file(Path::new(db_path));
    let pool = Pool::builder().max_size(16).build(manager)?;

    let conn = pool.get().map_err(|e| format!("Failed to get DB conn: {}", e))?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS signatures (
            hash TEXT PRIMARY KEY,
            type TEXT NOT NULL,
            verdict TEXT NOT NULL,
            metadata TEXT
        )",
        [],
    ).map_err(|e| format!("Schema init failed: {}", e))?;

    Ok(pool)
}