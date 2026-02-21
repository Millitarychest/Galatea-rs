use babel_api_definition::TelemetryEvent;
use mimic_core::error;
use rusqlite::params;

#[derive(Debug)]
pub struct TelemetryListItem {
    pub event_id: String,
    pub agent_id: String,
    pub agent_hostname: Option<String>,
    pub event_type: String,
    pub occurred_at: String,
    pub payload_json: String,
}

pub fn insert_events(
    pool: &super::DbPool,
    agent_id: &str,
    events: &[TelemetryEvent],
) -> error::Result<usize> {
    let mut conn = pool.get()?;
    let tx = conn.transaction()?;
    let mut inserted = 0usize;

    for event in events {
        let payload_json = serde_json::to_string(event)?;
        let rows = tx.execute(
            "INSERT OR IGNORE INTO telemetry_events (
                event_id,
                agent_id,
                event_type,
                occurred_at,
                ingested_at,
                payload_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                event.event_id().to_string(),
                agent_id,
                event.event_type(),
                event.occurred_at().to_rfc3339(),
                chrono::Utc::now().to_rfc3339(),
                payload_json
            ],
        )?;
        inserted += rows;
    }

    tx.commit()?;
    Ok(inserted)
}

pub fn get_recent_events(pool: &super::DbPool, limit: usize) -> error::Result<Vec<TelemetryListItem>> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare(
        "SELECT
            te.event_id,
            te.agent_id,
            a.hostname,
            te.event_type,
            te.occurred_at,
            te.payload_json
        FROM telemetry_events te
        LEFT JOIN agents a ON a.agent_id = te.agent_id
        ORDER BY datetime(te.occurred_at) DESC
        LIMIT ?1",
    )?;

    let rows = stmt
        .query_map(params![limit as i64], |row| {
            Ok(TelemetryListItem {
                event_id: row.get(0)?,
                agent_id: row.get(1)?,
                agent_hostname: row.get(2)?,
                event_type: row.get(3)?,
                occurred_at: row.get(4)?,
                payload_json: row.get(5)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(rows)
}

pub fn get_recent_events_for_agent(
    pool: &super::DbPool,
    agent_id: &str,
    limit: usize,
) -> error::Result<Vec<TelemetryListItem>> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare(
        "SELECT
            te.event_id,
            te.agent_id,
            a.hostname,
            te.event_type,
            te.occurred_at,
            te.payload_json
        FROM telemetry_events te
        LEFT JOIN agents a ON a.agent_id = te.agent_id
        WHERE te.agent_id = ?1
        ORDER BY datetime(te.occurred_at) DESC
        LIMIT ?2",
    )?;

    let rows = stmt
        .query_map(params![agent_id, limit as i64], |row| {
            Ok(TelemetryListItem {
                event_id: row.get(0)?,
                agent_id: row.get(1)?,
                agent_hostname: row.get(2)?,
                event_type: row.get(3)?,
                occurred_at: row.get(4)?,
                payload_json: row.get(5)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(rows)
}
