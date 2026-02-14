use api_definition::AgentRegistration;
use mimic_core::error;
use rusqlite::{OptionalExtension, Row};


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


/// Helper Struct: Representing the DB value of Agent status as a rust enum 
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

/// Register a Agent in the DB
pub fn register_agent(pool: &super::DbPool, registration: &AgentRegistration) -> error::Result<()> {
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

/// Fetches all registered Agents
pub fn get_all_agents(pool: &super::DbPool) -> error::Result<Vec<AgentInfo>> {
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

/// Fetches a single Agent by the ID
pub fn get_agent_by_id(pool: &super::DbPool, agent_id: &str) -> error::Result<Option<AgentInfo>> {
    let conn = pool.get()?;

    let mut stmt = conn.prepare(
        "SELECT agent_id, hostname, os_version, agent_version, ip_address, 
            last_heartbeat_at, registered_at, status 
            FROM agents WHERE agent_id = ?1",
    )?;

    let agent: Option<AgentInfo> = stmt.query_row([agent_id], row_to_agent).optional()?;

    Ok(agent)
}

/// Update the "last_heartbeat" Value of a given Agent
pub fn update_heartbeat(pool: &super::DbPool, agent_id: &str) -> error::Result<()> {
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

/// Marks Agents as offline if last hearbeat is older than timeout
pub fn mark_stale_agents_offline(
    pool: &super::DbPool,
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


/// Helper to convert database entry to AgentInfo struct
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

