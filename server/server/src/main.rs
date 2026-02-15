use std::{net::SocketAddr, path::PathBuf};
use clap::Parser;
use axum::{
    Router,
    routing::{get, post},
};
use tokio::time::{interval, sleep};
use tower_http::services::ServeDir;

use crate::{routes::{agent, api, dashboard, events}, state::{AppContext, set_startup_config}};

mod config;
mod state;
mod routes;
mod db;
mod utils;

/// Background task to mark stale agents as offline
async fn stale_agent_monitor() {
    let mut ticker = interval(config::HEARTBEAT_INTERVAL);
    
    loop {
        ticker.tick().await;

        let context = match AppContext::ensure_global() {
            Ok(context) => context,
            Err(e) => {
                mimic_core::mimic_log!("Skipping stale monitor tick: failed to get AppContext: {}", e);
                continue;
            }
        };
        match db::agent_db::mark_stale_agents_offline(&context.db_pool, config::AGENT_OFFLINE_TIMEOUT) {
            Ok(count) if count > 0 => {
                mimic_core::mimic_log!("Marked {} agent(s) as offline (no heartbeat)", count);
            }
            Ok(_) => {} // No agents to mark offline
            Err(e) => {
                mimic_core::mimic_log!("Error marking stale agents offline: {}", e);
            }
        }
    }
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    db_path: PathBuf,

    #[arg(short, long)]
    port: Option<u16>,
}


fn static_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")))
        .join("web/static")
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let port: u16 = match args.port {
        Some(inner) => inner,
        None =>  config::SERVER_PORT,
    };

    if let Err(e) = set_startup_config(args.db_path.clone(), port) {
        mimic_core::mimic_log!("Startup config initialization failed: {}", e);
        std::process::exit(1);
    }

    let db_path = match args.db_path.to_str() {
        Some(path) => path,
        None => {
            mimic_core::mimic_log!(
                "DB path contains invalid UTF-8 during startup: {:?}",
                args.db_path
            );
            std::process::exit(1);
        }
    };
    let db_pool = match db::init_db_pool(db_path) {
        Ok(pool) => pool,
        Err(e) => {
            mimic_core::mimic_log!("Failed to initialize DB pool: {}", e);
            std::process::exit(1);
        }
    };
    let context = AppContext::new(db_pool);
    if let Err(e) = context.set_global() {
        mimic_core::mimic_log!("Failed to set global AppContext: {}", e);
        std::process::exit(1);
    }

    let socket_addr = SocketAddr::from((config::SERVER_INTERFACE, port));


    tokio::spawn(stale_agent_monitor());

    let app = Router::new()
        // Web Routes
        .route("/", get(dashboard::serve_dashboard))
        .route("/agents/{id}", get(agent::serve_agent))
        .route("/events", get(events::serve_events))
        // API Routes
        .route("/api/v1/agents/register", post(api::handle_register))
        .route("/api/v1/agents/{id}/heartbeat", post(api::handle_heartbeat))
        .route("/api/v1/agents/{id}/telemetry", post(api::handle_telemetry))
        .route("/api/v1/agents/{id}/commands/{cmd_id}/ack", post(api::handle_command_ack))
        // Static files
        .nest_service("/static", ServeDir::new(static_dir()));

    mimic_core::mimic_log!("Galatea Server listening on http://{}", socket_addr);
    let mut backoff_secs: u64 = 1;
    loop {
        match axum_server::bind(socket_addr)
            .serve(app.clone().into_make_service())
            .await
        {
            Ok(_) => break,
            Err(e) => {
                mimic_core::mimic_log!(
                    "Server runtime error: {}. Retrying in {}s",
                    e,
                    backoff_secs
                );
                sleep(std::time::Duration::from_secs(backoff_secs)).await;
                backoff_secs = (backoff_secs * 2).min(30);
            }
        }
    }
}
