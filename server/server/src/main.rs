use std::{net::SocketAddr, path::PathBuf};
use clap::Parser;
use axum::{
    Router,
    routing::{get, post},
};
use tokio::time::interval;
use tower_http::services::ServeDir;

use crate::{routes::{agent, api, dashboard, events}, state::AppContext};

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
        
        let context = AppContext::global();
        match db::mark_stale_agents_offline(&context.db_pool, config::AGENT_OFFLINE_TIMEOUT) {
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
    let db_pool = db::init_db_pool(args.db_path.to_str().unwrap()).unwrap();
    let context = AppContext::new(db_pool);
    context.set_global().expect("Failed to set global AppContext");

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

    println!("Galatea Server listening on http://{}", socket_addr);
    axum_server::bind(socket_addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
