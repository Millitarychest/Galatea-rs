use std::path::Path;

use mimic_core::error;
use mimic_core::mimic_log;

use api_definition::AgentRegistration;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::OptionalExtension;
use rusqlite::Row;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentStatus {
    Online,
    Stale,
    Offline,
}

impl AgentStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            AgentStatus::Online => "online",
            AgentStatus::Stale => "stale",
            AgentStatus::Offline => "offline",
        }
    }

    pub fn class(&self) -> &'static str {
        match self {
            AgentStatus::Online => "online",
            AgentStatus::Stale => "stale",
            AgentStatus::Offline => "offline",
        }
    }
}

impl TryFrom<&str> for AgentStatus {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.to_lowercase().as_str() {
            "online" => Ok(AgentStatus::Online),
            "stale" => Ok(AgentStatus::Stale),
            "offline" => Ok(AgentStatus::Offline),
            _ => Err(format!("Unknown status: {}", value)),
        }
    }
}

#[derive(Debug)]
pub struct AgentInfo {
    pub agent_id: String,
    pub hostname: String,
    pub os_version: String,
    pub agent_version: String,
    pub ip_address: String,
    pub last_heartbeat_at: Option<String>,
    pub registered_at: String,
    pub status: AgentStatus,
}

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
    )",
];

pub type DbPool = Pool<SqliteConnectionManager>;

pub fn init_db_pool(db_path: &str) -> error::Result<DbPool> {
    mimic_log!("Initializing Database at: {}", db_path);

    let manager = SqliteConnectionManager::file(Path::new(db_path));
    let pool = Pool::builder().max_size(16).build(manager)?;

    let conn = pool
        .get()
        .map_err(|e| format!("Failed to get DB conn: {}", e))?;

    for statement in SQL_INIT_STATMENTS {
        conn.execute(statement, [])
            .map_err(|e| format!("Schema init failed: {}", e))?;
    }

    Ok(pool)
}

pub fn register_agent(pool: &DbPool, registration: &AgentRegistration) -> error::Result<()> {
    let conn = pool.get()?;
    let now = chrono::Utc::now().to_rfc3339();

    conn.execute(
        "INSERT INTO agents (agent_id, hostname, os_version, agent_version, ip_address, registered_at, last_heartbeat_at, status)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        [
            &registration.uuid.to_string(),
            &registration.host_info.hostname,
            &registration.host_info.os_version,
            &registration.host_info.agent_version,
            &registration.host_info.ip_address.clone().unwrap_or_default(),
            &now,
            &now, 
            AgentStatus::Online.as_str(),
        ],
    )?;

    Ok(())
}

fn row_to_agent(row: &Row) -> rusqlite::Result<AgentInfo> {
    let status_str: String = row.get(7)?;
    let status = AgentStatus::try_from(status_str.as_str())
        .map_err(|e| rusqlite::Error::InvalidColumnType(7, e, rusqlite::types::Type::Text))?;

    Ok(AgentInfo {
        agent_id: row.get(0)?,
        hostname: row.get(1)?,
        os_version: row.get(2)?,
        agent_version: row.get(3)?,
        ip_address: row.get(4)?,
        last_heartbeat_at: row.get(5)?,
        registered_at: row.get(6)?,
        status,
    })
}

pub fn get_all_agents(pool: &DbPool) -> error::Result<Vec<AgentInfo>> {
    let conn = pool.get()?;

    let mut stmt = conn.prepare(
        "SELECT agent_id, hostname, os_version, agent_version, ip_address, 
            last_heartbeat_at, registered_at, status 
            FROM agents",
    )?;

    let agents: Vec<AgentInfo> = stmt
        .query_map([], row_to_agent)?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(agents)
}

pub fn get_agent_by_id(pool: &DbPool, agent_id: &str) -> error::Result<Option<AgentInfo>> {
    let conn = pool.get()?;

    let mut stmt = conn.prepare(
        "SELECT agent_id, hostname, os_version, agent_version, ip_address, 
            last_heartbeat_at, registered_at, status 
            FROM agents WHERE agent_id = ?1",
    )?;

    let agent: Option<AgentInfo> = stmt.query_row([agent_id], row_to_agent).optional()?;

    Ok(agent)
}

pub fn update_heartbeat(pool: &DbPool, agent_id: &str) -> error::Result<()> {
    let conn = pool.get()?;

    conn.execute(
        "UPDATE agents 
            SET last_heartbeat_at = ?1, status = ?2
            WHERE agent_id = ?3",
        [
            chrono::Utc::now().to_rfc3339(),
            AgentStatus::Online.as_str().to_string(),
            agent_id.to_string(),
        ],
    )?;

    Ok(())
}

#[derive(Debug)]
pub struct PendingCommand {
    pub command_id: String,
    pub command_type: String,
    pub payload_json: Option<String>,
}

pub fn get_pending_commands(pool: &DbPool, agent_id: &str) -> error::Result<Vec<PendingCommand>> {
    let conn = pool.get()?;

    let mut stmt = conn.prepare(
        "SELECT command_id, command_type, payload_json 
            FROM commands 
            WHERE agent_id = ?1 AND status = 'pending'
            ORDER BY created_at ASC",
    )?;

    let commands: Vec<PendingCommand> = stmt
        .query_map([agent_id], |row| {
            Ok(PendingCommand {
                command_id: row.get(0)?,
                command_type: row.get(1)?,
                payload_json: row.get(2)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(commands)
}

pub fn mark_command_delivered(pool: &DbPool, command_id: &str) -> error::Result<()> {
    let conn = pool.get()?;

    conn.execute(
        "UPDATE commands 
            SET status = 'delivered', delivered_at = ?1
            WHERE command_id = ?2",
        [chrono::Utc::now().to_rfc3339(), command_id.to_string()],
    )?;

    Ok(())
}


pub fn mark_stale_agents_offline(
    pool: &DbPool,
    timeout: std::time::Duration,
) -> error::Result<usize> {
    let conn = pool.get()?;
    let cutoff = chrono::Utc::now()
        - chrono::Duration::from_std(timeout).unwrap_or(chrono::Duration::seconds(90));

    let rows_affected = conn.execute(
        "UPDATE agents 
         SET status = 'offline'
         WHERE status = 'online' 
           AND COALESCE(
                 datetime(last_heartbeat_at), 
                 datetime(registered_at)
               ) < datetime(?1)",
        [cutoff.to_rfc3339()],
    )?;

    Ok(rows_affected)
}
