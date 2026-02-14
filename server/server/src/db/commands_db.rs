use mimic_core::error;


#[derive(Debug)]
pub struct PendingCommand {
    pub command_id: String,
    pub command_type: String,
    pub payload_json: Option<String>,
}

/// Helper Struct: Representing the DB value of Command status as a rust enum 
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmdStatus {
    Pending,
    Delivered,
    Completed,
}

impl CmdStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            CmdStatus::Pending => "pending",
            CmdStatus::Delivered => "delivered",
            CmdStatus::Completed => "completed",
        }
    }

}

impl TryFrom<&str> for CmdStatus {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value.to_lowercase().as_str() {
            "pending" => Ok(CmdStatus::Pending),
            "delivered" => Ok(CmdStatus::Delivered),
            "completed" => Ok(CmdStatus::Completed),
            _ => Err(format!("Unknown status: {}", value)),
        }
    }
}

/// Gets pending commands for a agent, ordered by creation time
pub fn get_pending_commands(pool: &super::DbPool, agent_id: &str) -> error::Result<Vec<PendingCommand>> {
    let conn = pool.get()?;

    let mut stmt = conn.prepare(
        "SELECT command_id, command_type, payload_json 
            FROM commands 
            WHERE agent_id = ?1 AND status = '?2'
            ORDER BY created_at ASC",
    )?;

    let commands: Vec<PendingCommand> = stmt
        .query_map([agent_id, CmdStatus::Pending.as_str()], |row| {
            Ok(PendingCommand {
                command_id: row.get(0)?,
                command_type: row.get(1)?,
                payload_json: row.get(2)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(commands)
}

/// Updates a commands status to delivered
pub fn mark_command_delivered(pool: &super::DbPool, command_id: &str) -> error::Result<()> {
    let conn = pool.get()?;

    conn.execute(
        "UPDATE commands 
            SET status = '?1', delivered_at = ?2
            WHERE command_id = ?3",
        [CmdStatus::Delivered.as_str(), &chrono::Utc::now().to_rfc3339(), command_id],
    )?;

    Ok(())
}


pub fn complete_command(pool: &super::DbPool, command_id: &str) -> error::Result<()> {
    let conn = pool.get()?;

    conn.execute(
        "UPDATE commands 
            SET status = '?1', acked_at = ?2
            WHERE command_id = ?3",
        [CmdStatus::Completed.as_str(), &chrono::Utc::now().to_rfc3339(), command_id],
    )?;

    Ok(())
}