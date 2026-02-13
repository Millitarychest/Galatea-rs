use std::path::Path;

use mimic_core::error;
use mimic_core::mimic_log;

use api_definition::AgentRegistration;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

const SQL_INIT_STATMENTS: [&str; 2] = [
    "CREATE TABLE IF NOT EXISTS agents (
        agent_id    TEXT PRIMARY KEY,
        hostname    TEXT NOT NULL,
        os_version  TEXT,
        agent_version TEXT,
        ip_address  TEXT,
        last_heartbeat_at TEXT,
        registered_at TEXT NOT NULL,
        status      TEXT DEFAULT 'offline'
    )",
    "CREATE TABLE IF NOT EXISTS commands (
        command_id   TEXT PRIMARY KEY,
        agent_id     TEXT NOT NULL REFERENCES agents(agent_id),
        command_type TEXT NOT NULL,
        payload_json TEXT,
        status       TEXT DEFAULT 'pending',
        created_at   TEXT NOT NULL,
        delivered_at TEXT,
        acked_at     TEXT
    )"
];


pub type DbPool = Pool<SqliteConnectionManager>;

pub fn init_db_pool(db_path: &str) -> error::Result<DbPool>{
    mimic_log!("Initializing Database at: {}", db_path);

    let manager = SqliteConnectionManager::file(Path::new(db_path));
    let pool = Pool::builder().max_size(16).build(manager)?;

    let conn = pool.get().map_err(|e| format!("Failed to get DB conn: {}", e))?;

    for statement in SQL_INIT_STATMENTS {
        conn.execute(statement,
            [],
        ).map_err(|e| format!("Schema init failed: {}", e))?;
    }
    
    Ok(pool)
}


pub fn register_agent(pool: &DbPool, registration: &AgentRegistration)-> error::Result<()> {
    let conn = pool.get()?;

    conn.execute(
        "INSERT INTO agents (agent_id, hostname, os_version, agent_version, ip_address, registered_at, status)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        [
            &registration.uuid.to_string(),
            &registration.host_info.hostname,
            &registration.host_info.os_version,
            &registration.host_info.agent_version,
            &registration.host_info.ip_address.clone().unwrap_or_default(),
            &chrono::Utc::now().to_rfc3339(),
            "online", // TODO: Need to change this field to a enum
        ],
    )?;
    
    Ok(())
}