use std::path::Path;

use mimic_core::{error, mimic_error, mimic_log};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::OptionalExtension;

pub type DbPool = Pool<SqliteConnectionManager>;

pub fn init_db_pool(db_path: &str) -> error::Result<DbPool> {
    mimic_log!("Initializing Database at: {}", db_path);

    let manager = SqliteConnectionManager::file(Path::new(db_path));
    let pool = Pool::builder().max_size(16).build(manager)?;

    let conn = pool
        .get()
        .map_err(|e| format!("Failed to get DB conn: {}", e))?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS signatures (
            hash TEXT PRIMARY KEY,
            type INTEGER NOT NULL DEFAULT 0,
            verdict INTEGER NOT NULL DEFAULT 100,
            meta TEXT
        )",
        [],
    )
    .map_err(|e| format!("Schema init failed: {}", e))?;

    Ok(pool)
}

#[derive(PartialEq)]
pub enum IocType {
    Md5Hash,

    Unknown,
}

pub struct SignatureRecord {
    pub hash: String,
    pub ioc_type: IocType,
    pub verdict: i32, //Score between 0-100 (100 Known bad)
    pub meta: String,
}

pub fn check_signature(pool: &DbPool, hash: &str) -> Option<SignatureRecord> {
    let conn = match pool.get() {
        Ok(c) => c,
        Err(e) => {
            mimic_error!("[DB-ERR] Failed to get connection: {}", e);
            return None;
        }
    };

    let mut stmt =
        match conn.prepare("SELECT hash, type, verdict, meta FROM signatures WHERE hash = ?1") {
            Ok(s) => s,
            Err(e) => {
                mimic_log!("[DB-ERR] Prepare failed: {}", e);
                return None;
            }
        };

    let result = stmt
        .query_row([hash], |row| {
            let raw_ioc: i32 = row.get(1)?;
            let ioc = match raw_ioc {
                0 => IocType::Md5Hash,
                _ => IocType::Unknown,
            };
            Ok(SignatureRecord {
                hash: row.get(0)?,
                ioc_type: ioc,
                verdict: row.get(2)?,
                meta: row.get(3)?,
            })
        })
        .optional();

    match result {
        Ok(opt) => opt,
        Err(e) => {
            mimic_error!("[DB-ERR] Query failed: {}", e);
            None
        }
    }
}
